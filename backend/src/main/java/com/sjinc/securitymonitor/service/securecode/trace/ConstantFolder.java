package com.sjinc.securitymonitor.service.securecode.trace;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.CharLiteralExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.DoubleLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.LongLiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.UnaryExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.BreakStmt;
import com.github.javaparser.ast.stmt.ContinueStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchEntry;
import com.github.javaparser.ast.stmt.SwitchStmt;
import com.github.javaparser.ast.stmt.ThrowStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.Declaration;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.FieldDecl;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex.LocalDecl;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 메서드 안에서 상수로 정해지는 값(리터럴, 한 번만 정해지는 지역 변수, static final 필드, 그 사이의 사칙연산·비교·문자열 메서드)을 계산해
 * <b>절대 실행되지 않는 갈래</b>를 가려낸다. ValueOriginTracer가 대입을 모두 모아 가장 나쁜 값으로 판정하다 보니
 * {@code switch ("ABC".charAt(1)) { case 'A': bar = param; case 'B': bar = "bob"; }}처럼 실제로는 안전한 갈래만 도는 코드를
 * 클라이언트 값으로 판정했다(OWASP Benchmark SQL 인젝션 오탐의 대부분).
 *
 * <p>모르면 계산하지 않는다(Optional.empty) — 그 갈래는 실행될 수 있다고 보고, 판정은 지금처럼 가장 나쁜 쪽으로 남는다. 안전으로 기울이지 않는다.
 *
 * <p>값 표현: 정수·char 연산 결과는 Long, 실수는 Double, char 리터럴·charAt 결과는 Character, 그 밖에 String·Boolean.
 */
final class ConstantFolder {

    /** 상수 계산 재귀 깊이. 지역 변수가 서로를 참조하는 모양에서 맴돌지 않게 한다. */
    private static final int MAX_DEPTH = 20;
    private static final Set<String> STRING_METHODS = Set.of("charAt", "length", "equals", "equalsIgnoreCase", "isEmpty",
            "startsWith", "endsWith", "contains", "indexOf", "substring", "toUpperCase", "toLowerCase", "trim");

    private final JavaSourceIndex java;

    ConstantFolder(JavaSourceIndex java) {
        this.java = java;
    }

    // ================================================================ 값 계산

    Optional<Object> value(Expression expression) {
        return Optional.ofNullable(eval(expression, 0));
    }

    /** 상수 조건이면 그 참/거짓. */
    Optional<Boolean> condition(Expression expression) {
        return eval(expression, 0) instanceof Boolean b ? Optional.of(b) : Optional.empty();
    }

    private Object eval(Expression expression, int depth) {
        if (depth > MAX_DEPTH) return null;
        Expression e = ValueOriginTracer.unwrap(expression);
        if (e instanceof IntegerLiteralExpr i) return i.asNumber().longValue();
        if (e instanceof LongLiteralExpr l) return l.asNumber().longValue();
        if (e instanceof DoubleLiteralExpr d) return d.asDouble();
        if (e instanceof CharLiteralExpr c) return c.asChar();
        if (e instanceof StringLiteralExpr s) return s.getValue();
        if (e instanceof BooleanLiteralExpr b) return b.getValue();
        if (e instanceof NameExpr name) return evalName(name, depth);
        if (e instanceof UnaryExpr unary) return evalUnary(unary, depth);
        if (e instanceof BinaryExpr binary) return evalBinary(binary, depth);
        if (e instanceof ConditionalExpr conditional) {
            Object cond = eval(conditional.getCondition(), depth + 1);
            if (!(cond instanceof Boolean b)) return null;
            return eval(b ? conditional.getThenExpr() : conditional.getElseExpr(), depth + 1);
        }
        if (e instanceof MethodCallExpr call) return evalStringMethod(call, depth);
        return null;
    }

    /** 한 번만 정해지는 지역 변수(초기값만 있고 대입·++/--가 없다)와 static final 필드. */
    private Object evalName(NameExpr name, int depth) {
        Optional<Declaration> declaration = java.declarationOf(name);
        if (declaration.isEmpty()) return null;
        if (declaration.get() instanceof FieldDecl field) {
            return field.field().isStatic() && field.field().isFinal() && field.variable().getInitializer().isPresent()
                    ? eval(field.variable().getInitializer().get(), depth + 1) : null;
        }
        if (declaration.get() instanceof LocalDecl local && local.forEach() == null && local.variable().getInitializer().isPresent()
                && !isReassigned(local.callable(), name.getNameAsString())) {
            return eval(local.variable().getInitializer().get(), depth + 1);
        }
        return null;
    }

    private static boolean isReassigned(CallableDeclaration<?> method, String id) {
        return method.findAll(AssignExpr.class).stream()
                .anyMatch(a -> a.getTarget() instanceof NameExpr t && t.getNameAsString().equals(id))
                || method.findAll(UnaryExpr.class).stream()
                .anyMatch(u -> isIncrement(u.getOperator()) && u.getExpression() instanceof NameExpr t && t.getNameAsString().equals(id));
    }

    private static boolean isIncrement(UnaryExpr.Operator op) {
        return op == UnaryExpr.Operator.PREFIX_INCREMENT || op == UnaryExpr.Operator.PREFIX_DECREMENT
                || op == UnaryExpr.Operator.POSTFIX_INCREMENT || op == UnaryExpr.Operator.POSTFIX_DECREMENT;
    }

    private Object evalUnary(UnaryExpr unary, int depth) {
        Object v = eval(unary.getExpression(), depth + 1);
        return switch (unary.getOperator()) {
            case LOGICAL_COMPLEMENT -> v instanceof Boolean b ? !b : null;
            case MINUS -> v instanceof Double d ? (Object) (-d) : integral(v) != null ? (Object) (-integral(v)) : null;
            case PLUS -> v instanceof Double || integral(v) != null ? numeric(v) : null;
            default -> null;
        };
    }

    private Object evalBinary(BinaryExpr binary, int depth) {
        BinaryExpr.Operator op = binary.getOperator();
        Object left = eval(binary.getLeft(), depth + 1);
        // &&·||는 왼쪽만으로 정해지면 오른쪽을 보지 않는다(오른쪽이 상수가 아니어도 된다).
        if (op == BinaryExpr.Operator.AND && Boolean.FALSE.equals(left)) return false;
        if (op == BinaryExpr.Operator.OR && Boolean.TRUE.equals(left)) return true;
        if (left == null) return null;
        Object right = eval(binary.getRight(), depth + 1);
        if (right == null) return null;
        if (op == BinaryExpr.Operator.AND || op == BinaryExpr.Operator.OR) {
            return left instanceof Boolean l && right instanceof Boolean r ? (op == BinaryExpr.Operator.AND ? l && r : l || r) : null;
        }
        if (op == BinaryExpr.Operator.PLUS && (left instanceof String || right instanceof String)) {
            return String.valueOf(left) + right;
        }
        if (op == BinaryExpr.Operator.EQUALS || op == BinaryExpr.Operator.NOT_EQUALS) {
            Boolean same = sameValue(left, right);
            return same == null ? null : (op == BinaryExpr.Operator.EQUALS) == same;
        }
        Object l = numeric(left), r = numeric(right);
        if (l == null || r == null) return null;
        if (l instanceof Double || r instanceof Double) {
            double a = ((Number) l).doubleValue(), b = ((Number) r).doubleValue();
            return switch (op) {
                case PLUS -> a + b;
                case MINUS -> a - b;
                case MULTIPLY -> a * b;
                case DIVIDE -> a / b;
                case LESS -> a < b;
                case LESS_EQUALS -> a <= b;
                case GREATER -> a > b;
                case GREATER_EQUALS -> a >= b;
                default -> null;
            };
        }
        long a = (Long) l, b = (Long) r;
        return switch (op) {
            case PLUS -> a + b;
            case MINUS -> a - b;
            case MULTIPLY -> a * b;
            case DIVIDE -> b == 0 ? null : (Object) (a / b);
            case REMAINDER -> b == 0 ? null : (Object) (a % b);
            case LESS -> a < b;
            case LESS_EQUALS -> a <= b;
            case GREATER -> a > b;
            case GREATER_EQUALS -> a >= b;
            default -> null;
        };
    }

    /** 상수 문자열에 부르는 JDK String 메서드("ABC".charAt(1), guess.length()). */
    private Object evalStringMethod(MethodCallExpr call, int depth) {
        if (call.getScope().isEmpty() || !STRING_METHODS.contains(call.getNameAsString())) return null;
        if (!(eval(call.getScope().get(), depth + 1) instanceof String s)) return null;
        List<Object> args = new ArrayList<>();
        for (Expression arg : call.getArguments()) {
            Object v = eval(arg, depth + 1);
            if (v == null) return null;
            args.add(v);
        }
        try {
            return switch (call.getNameAsString() + "/" + args.size()) {
                case "charAt/1" -> integral(args.get(0)) == null ? null : (Object) s.charAt(integral(args.get(0)).intValue());
                case "length/0" -> (long) s.length();
                case "isEmpty/0" -> s.isEmpty();
                case "trim/0" -> s.trim();
                case "toUpperCase/0" -> s.toUpperCase();
                case "toLowerCase/0" -> s.toLowerCase();
                case "equals/1" -> s.equals(args.get(0));
                case "equalsIgnoreCase/1" -> args.get(0) instanceof String o ? (Object) s.equalsIgnoreCase(o) : null;
                case "startsWith/1" -> args.get(0) instanceof String o ? (Object) s.startsWith(o) : null;
                case "endsWith/1" -> args.get(0) instanceof String o ? (Object) s.endsWith(o) : null;
                case "contains/1" -> args.get(0) instanceof String o ? (Object) s.contains(o) : null;
                case "indexOf/1" -> args.get(0) instanceof String o ? (Object) (long) s.indexOf(o)
                        : integral(args.get(0)) != null ? (Object) (long) s.indexOf(integral(args.get(0)).intValue()) : null;
                case "substring/1" -> integral(args.get(0)) == null ? null : s.substring(integral(args.get(0)).intValue());
                case "substring/2" -> integral(args.get(0)) == null || integral(args.get(1)) == null ? null
                        : s.substring(integral(args.get(0)).intValue(), integral(args.get(1)).intValue());
                default -> null;
            };
        } catch (IndexOutOfBoundsException ex) {
            return null; // 실행하면 예외가 나는 코드 — 계산하지 않는다.
        }
    }

    /** 숫자·문자는 수로, 문자열·불리언은 그대로 비교. 종류가 달라 판단할 수 없으면 null. */
    private static Boolean sameValue(Object a, Object b) {
        Object x = numeric(a), y = numeric(b);
        if (x != null && y != null) return ((Number) x).doubleValue() == ((Number) y).doubleValue();
        if (a instanceof Boolean && b instanceof Boolean) return a.equals(b);
        return null; // 문자열 ==는 참조 비교라 값으로 정할 수 없다.
    }

    private static Object numeric(Object v) {
        if (v instanceof Double) return v;
        return integral(v);
    }

    private static Long integral(Object v) {
        if (v instanceof Long l) return l;
        if (v instanceof Character c) return (long) c;
        return null;
    }

    // ================================================================ 실행되지 않는 갈래

    /**
     * node가 상수 조건 때문에 절대 실행되지 않는 갈래 안에 있는가 — if의 반대쪽, 삼항의 반대쪽, 선택값이 상수인 switch에서 닿지 않는 case,
     * {@code while (false)}. 감싼 메서드(람다 포함 바깥 메서드)까지 올라가며 본다.
     */
    boolean isDead(Node node) {
        Node child = node;
        while (child.getParentNode().isPresent()) {
            Node parent = child.getParentNode().get();
            if (parent instanceof CallableDeclaration) return false;
            if (parent instanceof IfStmt ifStmt && child != ifStmt.getCondition()) {
                Optional<Boolean> cond = condition(ifStmt.getCondition());
                if (cond.isPresent() && cond.get() != (child == ifStmt.getThenStmt())) return true;
            }
            if (parent instanceof ConditionalExpr conditional && child != conditional.getCondition()) {
                Optional<Boolean> cond = condition(conditional.getCondition());
                if (cond.isPresent() && cond.get() != (child == conditional.getThenExpr())) return true;
            }
            if (parent instanceof WhileStmt loop && child == loop.getBody() && condition(loop.getCondition()).equals(Optional.of(false))) {
                return true;
            }
            if (parent instanceof SwitchEntry entry && entry.getParentNode().orElse(null) instanceof SwitchStmt switchStmt
                    && !entry.getLabels().contains(child)) {
                Optional<List<SwitchEntry>> reached = reachedEntries(switchStmt);
                if (reached.isPresent() && reached.get().stream().noneMatch(r -> r == entry)) return true;
            }
            child = parent;
        }
        return false;
    }

    /**
     * 선택값이 상수인 switch에서 실제로 실행되는 case들 — 맞는 case(없으면 default)부터 break·return·throw로 끝나는 case까지
     * (fall-through 포함). 선택값이나 case 값을 계산하지 못하면 empty.
     */
    private Optional<List<SwitchEntry>> reachedEntries(SwitchStmt switchStmt) {
        Object selector = eval(switchStmt.getSelector(), 0);
        if (selector == null) return Optional.empty();
        List<SwitchEntry> entries = switchStmt.getEntries();
        int start = -1;
        for (int i = 0; i < entries.size() && start < 0; i++) {
            for (Expression label : entries.get(i).getLabels()) {
                Object v = eval(label, 0);
                if (v == null) return Optional.empty();
                if (selector.equals(v) || Boolean.TRUE.equals(sameValue(selector, v))) {
                    start = i;
                    break;
                }
            }
        }
        if (start < 0) {
            for (int i = 0; i < entries.size(); i++) {
                if (entries.get(i).getLabels().isEmpty()) start = i;
            }
        }
        List<SwitchEntry> reached = new ArrayList<>();
        if (start < 0) return Optional.of(reached); // 맞는 case도 default도 없다 — 아무 것도 실행되지 않는다.
        for (int i = start; i < entries.size(); i++) {
            SwitchEntry entry = entries.get(i);
            reached.add(entry);
            // 화살표 case(case 'A' -> ...)는 fall-through가 없다.
            if (entry.getType() != SwitchEntry.Type.STATEMENT_GROUP || endsAbruptly(entry.getStatements())) break;
        }
        return Optional.of(reached);
    }

    private static boolean endsAbruptly(List<Statement> statements) {
        if (statements.isEmpty()) return false;
        Statement last = statements.get(statements.size() - 1);
        if (last instanceof BlockStmt block) return endsAbruptly(block.getStatements());
        return last instanceof BreakStmt || last instanceof ReturnStmt || last instanceof ThrowStmt || last instanceof ContinueStmt;
    }

    // ================================================================ 리스트 위치 계산

    /**
     * {@code list.get(i)}가 꺼내는 원소 식. 지역 리스트를 빈 값으로 만들고 같은 블록에서 차례로 add·remove·set만 한 뒤 상수 위치로 꺼낼 때만
     * 계산한다({@code add("safe"); add(param); add("moresafe"); remove(0); get(1)} → "moresafe"). 조건·반복 안에서 바꾸거나 다른 곳에 넘기면 empty.
     */
    Optional<Expression> listElement(MethodCallExpr get, LocalDecl local) {
        String id = local.variable().getNameAsString();
        if (!get.getNameAsString().equals("get") || get.getArguments().size() != 1) return Optional.empty();
        if (!(eval(get.getArgument(0), 0) instanceof Long index)) return Optional.empty();
        Optional<Expression> init = local.variable().getInitializer().map(ValueOriginTracer::unwrap);
        if (init.isEmpty() || !(init.get() instanceof ObjectCreationExpr creation) || !creation.getArguments().isEmpty()) {
            return Optional.empty();
        }
        Statement declStmt = local.variable().findAncestor(Statement.class).orElse(null);
        Statement getStmt = statementIn(get, declStmt == null ? null : declStmt.getParentNode().orElse(null));
        if (declStmt == null || getStmt == null || !(declStmt.getParentNode().orElse(null) instanceof BlockStmt block)) {
            return Optional.empty();
        }
        // 선언과 꺼내는 문장 사이에서 이 리스트를 쓰는 곳은 모두 같은 블록의 "list.메서드(...);" 문장이어야 한다.
        List<MethodCallExpr> ops = new ArrayList<>();
        for (NameExpr use : local.callable().findAll(NameExpr.class)) {
            if (!use.getNameAsString().equals(id) || !ValueOriginTracer.before(declStmt, use) || !ValueOriginTracer.before(use, getStmt)) {
                continue;
            }
            if (!(use.getParentNode().orElse(null) instanceof MethodCallExpr op) || op.getScope().orElse(null) != use
                    || !(op.getParentNode().orElse(null) instanceof ExpressionStmt stmt) || stmt.getParentNode().orElse(null) != block) {
                return Optional.empty();
            }
            ops.add(op);
        }
        List<Expression> elements = new ArrayList<>();
        try {
            for (MethodCallExpr op : ops) {
                List<Expression> args = op.getArguments();
                switch (op.getNameAsString() + "/" + args.size()) {
                    case "add/1" -> elements.add(args.get(0));
                    case "add/2" -> elements.add(intArg(args.get(0)), args.get(1));
                    case "set/2" -> elements.set(intArg(args.get(0)), args.get(1));
                    case "remove/1" -> elements.remove(intArg(args.get(0)));
                    case "clear/0" -> elements.clear();
                    case "get/1", "size/0", "isEmpty/0", "contains/1", "indexOf/1" -> { }
                    default -> {
                        return Optional.empty();
                    }
                }
            }
            return Optional.of(elements.get(index.intValue()));
        } catch (IndexOutOfBoundsException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /** 정수 상수 인자. remove("safe")처럼 값으로 지우는 호출·모르는 위치는 계산하지 않는다. */
    private int intArg(Expression arg) {
        if (eval(arg, 0) instanceof Long l) return l.intValue();
        throw new IllegalArgumentException("상수 위치가 아님");
    }

    /** node를 품은, block 바로 아래의 문장. */
    private static Statement statementIn(Node node, Node block) {
        Node child = node;
        while (child.getParentNode().isPresent()) {
            Node parent = child.getParentNode().get();
            if (parent == block) return child instanceof Statement s ? s : null;
            child = parent;
        }
        return null;
    }
}
