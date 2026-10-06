package com.sjinc.cvemonitor.service.securecode;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.ThisExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;
import com.github.javaparser.ast.stmt.CatchClause;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.type.ClassOrInterfaceType;
import com.github.javaparser.ast.type.Type;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 점검 대상 저장소의 Java 소스를 구문 분석해 두고, 추적에 필요한 질문(이 이름은 어디서 선언됐나, 이 호출은 어느 메서드인가,
 * 이 메서드를 누가 부르나)에 답한다.
 *
 * <p>타입 해석기(symbol solver)를 쓰지 않는다 — 대상 앱의 의존 라이브러리 jar 없이 소스만 있는 상태라 정확한 해석이 안 되고,
 * 느리다. 대신 "변수·필드·파라미터의 선언 타입 이름 = 우리 소스의 클래스 이름"으로 호출을 잇는다. Spring 주입 필드
 * ({@code private final Crc020Service crc020Service})가 대부분이라 이 정도로 충분하고, 못 이으면 추적기가 "판정 불가"로 남긴다.
 */
final class JavaSourceIndex {

    /** 이름 하나의 선언. 파라미터·지역 변수·필드·람다 파라미터(타입 모름) 중 하나. */
    sealed interface Declaration permits ParamDecl, LocalDecl, FieldDecl, LambdaParamDecl {
    }

    record ParamDecl(Parameter parameter, CallableDeclaration<?> callable, int index) implements Declaration {
    }

    /** 지역 변수. forEach가 있으면 향상된 for 문의 변수다(값은 반복 대상에서 온다). */
    record LocalDecl(VariableDeclarator variable, CallableDeclaration<?> callable, ForEachStmt forEach)
            implements Declaration {
    }

    record FieldDecl(VariableDeclarator variable, FieldDeclaration field) implements Declaration {
    }

    record LambdaParamDecl(Parameter parameter) implements Declaration {
    }

    private static final Set<String> MAPPING_ANNOTATIONS = Set.of(
            "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping");
    private static final Set<String> CONTROLLER_ANNOTATIONS = Set.of("Controller", "RestController");

    private final Map<CompilationUnit, String> paths = new IdentityHashMap<>();
    private final Map<String, List<ClassOrInterfaceDeclaration>> classesByName = new HashMap<>();
    private final Map<String, List<MethodCallExpr>> callsByName = new HashMap<>();
    private final List<String> failedFiles = new ArrayList<>();
    private final Map<MethodCallExpr, List<MethodDeclaration>> resolveCache = new IdentityHashMap<>();
    private final Map<MethodDeclaration, List<MethodCallExpr>> callersCache = new IdentityHashMap<>();

    /** @param sources 저장소 루트 기준 경로 → 소스 내용(.java만) */
    static JavaSourceIndex build(Map<String, String> sources) {
        JavaSourceIndex index = new JavaSourceIndex();
        JavaParser parser = new JavaParser(new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)
                .setAttributeComments(false));
        sources.forEach((path, content) -> {
            ParseResult<CompilationUnit> result = parser.parse(content);
            if (result.getResult().isEmpty() || !result.isSuccessful()) {
                // 못 읽은 파일은 그 파일 안의 호출·세팅을 못 본다는 뜻 — 조용히 넘기지 않고 위로 올린다.
                index.failedFiles.add(path);
                if (result.getResult().isEmpty()) return;
            }
            CompilationUnit unit = result.getResult().get();
            index.paths.put(unit, path);
            unit.findAll(ClassOrInterfaceDeclaration.class).forEach(type ->
                    index.classesByName.computeIfAbsent(type.getNameAsString(), k -> new ArrayList<>()).add(type));
            unit.findAll(MethodCallExpr.class).forEach(call ->
                    index.callsByName.computeIfAbsent(call.getNameAsString(), k -> new ArrayList<>()).add(call));
        });
        return index;
    }

    List<String> failedFiles() {
        return failedFiles;
    }

    /** 우리 소스의 모든 클래스·인터페이스. */
    List<ClassOrInterfaceDeclaration> allClasses() {
        return classesByName.values().stream().flatMap(List::stream).toList();
    }

    List<MethodCallExpr> callsNamed(String name) {
        return callsByName.getOrDefault(name, List.of());
    }

    /** "Crc020Service.java:102" — 근거 표시용. */
    String location(Node node) {
        String path = node.findCompilationUnit().map(paths::get).orElse("?");
        String file = path.substring(path.lastIndexOf('/') + 1);
        return file + ":" + node.getBegin().map(p -> p.line).orElse(0);
    }

    // ---------------------------------------------------------------- 이름 해석

    Optional<Declaration> declarationOf(NameExpr name) {
        String id = name.getNameAsString();
        Node node = name;
        while (node.getParentNode().isPresent()) {
            Node parent = node.getParentNode().get();
            if (parent instanceof LambdaExpr lambda) {
                for (Parameter p : lambda.getParameters()) {
                    if (p.getNameAsString().equals(id)) return Optional.of(new LambdaParamDecl(p));
                }
            }
            if (parent instanceof CatchClause catchClause && catchClause.getParameter().getNameAsString().equals(id)) {
                return Optional.of(new LambdaParamDecl(catchClause.getParameter()));
            }
            if (parent instanceof CallableDeclaration<?> callable) {
                List<Parameter> params = callable.getParameters();
                for (int i = 0; i < params.size(); i++) {
                    if (params.get(i).getNameAsString().equals(id)) return Optional.of(new ParamDecl(params.get(i), callable, i));
                }
                for (VariableDeclarator v : callable.findAll(VariableDeclarator.class)) {
                    if (v.getNameAsString().equals(id) && !(v.getParentNode().orElse(null) instanceof FieldDeclaration)) {
                        ForEachStmt forEach = v.findAncestor(ForEachStmt.class)
                                .filter(f -> f.getVariable().getVariables().contains(v)).orElse(null);
                        return Optional.of(new LocalDecl(v, callable, forEach));
                    }
                }
            }
            if (parent instanceof ClassOrInterfaceDeclaration type) {
                Optional<FieldDecl> field = field(type, id);
                if (field.isPresent()) return Optional.of(field.get());
            }
            node = parent;
        }
        return Optional.empty();
    }

    /** 클래스와 그 상위 클래스(우리 소스에 있는 것)에서 필드를 찾는다. */
    Optional<FieldDecl> field(ClassOrInterfaceDeclaration type, String name) {
        Set<ClassOrInterfaceDeclaration> seen = new LinkedHashSet<>();
        List<ClassOrInterfaceDeclaration> queue = new ArrayList<>(List.of(type));
        while (!queue.isEmpty()) {
            ClassOrInterfaceDeclaration current = queue.remove(0);
            if (!seen.add(current)) continue;
            for (FieldDeclaration f : current.getFields()) {
                for (VariableDeclarator v : f.getVariables()) {
                    if (v.getNameAsString().equals(name)) return Optional.of(new FieldDecl(v, f));
                }
            }
            for (ClassOrInterfaceType ext : current.getExtendedTypes()) {
                queue.addAll(classesByName.getOrDefault(ext.getNameAsString(), List.of()));
            }
        }
        return Optional.empty();
    }

    /** 선언 타입의 단순 이름(제네릭·패키지 제거). 모르면 null. */
    String typeNameOf(Declaration declaration) {
        Type type;
        if (declaration instanceof ParamDecl p) type = p.parameter().getType();
        else if (declaration instanceof LocalDecl l) type = l.variable().getType();
        else if (declaration instanceof FieldDecl f) type = f.variable().getType();
        else type = ((LambdaParamDecl) declaration).parameter().getType();
        if (type.isVarType() && declaration instanceof LocalDecl local) {
            return local.variable().getInitializer()
                    .filter(Expression::isObjectCreationExpr)
                    .map(init -> init.asObjectCreationExpr().getType().getNameAsString())
                    .orElse(null);
        }
        if (type.isUnknownType()) return null;
        return simpleName(type);
    }

    static String simpleName(Type type) {
        if (type instanceof ClassOrInterfaceType classType) return classType.getNameAsString();
        return type.asString();
    }

    /** 식의 정적 타입 이름(이름·this.필드·new 정도만). 모르면 null. */
    String typeNameOf(Expression expression) {
        if (expression instanceof NameExpr name) {
            return declarationOf(name).map(this::typeNameOf).orElse(null);
        }
        if (expression instanceof FieldAccessExpr access && access.getScope() instanceof ThisExpr) {
            return access.findAncestor(ClassOrInterfaceDeclaration.class)
                    .flatMap(type -> field(type, access.getNameAsString()))
                    .map(this::typeNameOf).orElse(null);
        }
        if (expression instanceof ObjectCreationExpr creation) {
            return creation.getType().getNameAsString();
        }
        return null;
    }

    // ---------------------------------------------------------------- 호출 잇기

    /** 이 호출이 가리키는 우리 소스의 메서드들. 외부 라이브러리 메서드면 빈 목록. */
    List<MethodDeclaration> resolve(MethodCallExpr call) {
        return resolveCache.computeIfAbsent(call, this::doResolve);
    }

    private List<MethodDeclaration> doResolve(MethodCallExpr call) {
        String name = call.getNameAsString();
        int arity = call.getArguments().size();
        List<ClassOrInterfaceDeclaration> owners;
        if (call.getScope().isEmpty() || call.getScope().get() instanceof ThisExpr) {
            owners = call.findAncestor(ClassOrInterfaceDeclaration.class).map(List::of).orElse(List.of());
        } else {
            Expression scope = call.getScope().get();
            String typeName = typeNameOf(scope);
            if (typeName == null && scope instanceof NameExpr n && Character.isUpperCase(n.getNameAsString().charAt(0))) {
                typeName = n.getNameAsString(); // 정적 호출(FrameEtcUtil.addUserInfo)
            }
            if (typeName == null) return List.of();
            owners = classesByName.getOrDefault(typeName, List.of());
        }
        List<MethodDeclaration> found = new ArrayList<>();
        for (ClassOrInterfaceDeclaration owner : withHierarchy(owners)) {
            for (MethodDeclaration method : owner.getMethodsByName(name)) {
                if (method.getParameters().size() == arity && method.getBody().isPresent()) found.add(method);
            }
        }
        return found;
    }

    /** 클래스 + 상위 클래스 + (인터페이스면) 구현 클래스. 주입 필드 타입이 인터페이스여도 실제 본문을 찾기 위함. */
    private List<ClassOrInterfaceDeclaration> withHierarchy(List<ClassOrInterfaceDeclaration> owners) {
        Set<ClassOrInterfaceDeclaration> result = new LinkedHashSet<>();
        List<ClassOrInterfaceDeclaration> queue = new ArrayList<>(owners);
        while (!queue.isEmpty()) {
            ClassOrInterfaceDeclaration current = queue.remove(0);
            if (!result.add(current)) continue;
            for (ClassOrInterfaceType ext : current.getExtendedTypes()) {
                queue.addAll(classesByName.getOrDefault(ext.getNameAsString(), List.of()));
            }
            if (current.isInterface()) {
                for (List<ClassOrInterfaceDeclaration> classes : classesByName.values()) {
                    for (ClassOrInterfaceDeclaration c : classes) {
                        if (c.getImplementedTypes().stream().anyMatch(t -> t.getNameAsString().equals(current.getNameAsString()))) {
                            queue.add(c);
                        }
                    }
                }
            }
        }
        return new ArrayList<>(result);
    }

    /** 우리 소스의 클래스 type이 상속 사슬 어딘가에서 bases 중 하나를 상속하는가(class BaseParam extends HashMap). */
    boolean extendsAny(String type, Set<String> bases) {
        Set<String> seen = new LinkedHashSet<>();
        List<String> queue = new ArrayList<>(List.of(type));
        while (!queue.isEmpty()) {
            String current = queue.remove(0);
            if (!seen.add(current)) continue;
            for (ClassOrInterfaceDeclaration c : classesByName.getOrDefault(current, List.of())) {
                for (ClassOrInterfaceType ext : c.getExtendedTypes()) {
                    if (bases.contains(ext.getNameAsString())) return true;
                    queue.add(ext.getNameAsString());
                }
            }
        }
        return false;
    }

    /** 이 메서드를 부르는 곳들. */
    List<MethodCallExpr> callersOf(MethodDeclaration method) {
        return callersCache.computeIfAbsent(method, m -> callsNamed(m.getNameAsString()).stream()
                .filter(call -> resolve(call).contains(m))
                .toList());
    }

    // ---------------------------------------------------------------- 컨트롤러

    /** Spring 컨트롤러의 요청 매핑 메서드인가 — 여기 파라미터는 클라이언트가 보낸 값이다. */
    boolean isHandler(CallableDeclaration<?> callable) {
        if (!(callable instanceof MethodDeclaration method)) return false;
        boolean mapped = method.getAnnotations().stream().anyMatch(a -> MAPPING_ANNOTATIONS.contains(a.getNameAsString()));
        boolean controller = method.findAncestor(TypeDeclaration.class)
                .map(type -> ((TypeDeclaration<?>) type).getAnnotations().stream()
                        .anyMatch(a -> CONTROLLER_ANNOTATIONS.contains(a.getNameAsString())))
                .orElse(false);
        return mapped && controller;
    }

    /** "POST /crc020/extra" 같은 표시. 값을 못 읽으면 메서드 이름. */
    String handlerLabel(CallableDeclaration<?> callable) {
        String prefix = callable.findAncestor(TypeDeclaration.class)
                .flatMap(type -> mappingValue(((TypeDeclaration<?>) type).getAnnotations())).orElse("");
        String path = mappingValue(callable.getAnnotations()).orElse("");
        String verb = callable.getAnnotations().stream()
                .map(AnnotationExpr::getNameAsString)
                .filter(MAPPING_ANNOTATIONS::contains)
                .findFirst()
                .map(n -> n.equals("RequestMapping") ? "" : n.replace("Mapping", "").toUpperCase() + " ")
                .orElse("");
        String url = (prefix + path).replace("//", "/");
        return url.isEmpty() ? callable.getNameAsString() : verb + url;
    }

    private static Optional<String> mappingValue(List<AnnotationExpr> annotations) {
        for (AnnotationExpr annotation : annotations) {
            if (!MAPPING_ANNOTATIONS.contains(annotation.getNameAsString())) continue;
            Expression value = null;
            if (annotation instanceof SingleMemberAnnotationExpr single) {
                value = single.getMemberValue();
            } else if (annotation instanceof NormalAnnotationExpr normal) {
                for (MemberValuePair pair : normal.getPairs()) {
                    if (pair.getNameAsString().equals("value") || pair.getNameAsString().equals("path")) value = pair.getValue();
                }
            }
            if (value != null && value.isArrayInitializerExpr() && value.asArrayInitializerExpr().getValues().isNonEmpty()) {
                value = value.asArrayInitializerExpr().getValues().get(0);
            }
            if (value instanceof StringLiteralExpr literal) return Optional.of(literal.getValue());
        }
        return Optional.empty();
    }

    /** 메서드·파라미터·필드·클래스 등 어노테이션을 붙일 수 있는 선언에 이 이름(@ 없이, 단순 이름)의 어노테이션이 있는가. */
    static boolean hasAnnotation(Node node, String name) {
        return node instanceof NodeWithAnnotations<?> annotated
                && annotated.getAnnotations().stream().anyMatch(a -> a.getNameAsString().equals(name));
    }
}
