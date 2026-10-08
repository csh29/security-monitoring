package com.sjinc.securitymonitor.service.securecode.tracerule;

import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules.FrameworkFact;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.assertj.core.api.Assertions.assertThat;
import com.sjinc.securitymonitor.service.securecode.trace.JavaSourceIndex;

class FrameworkProfilerTest {

    @Test
    void 빌드_파일_web_xml_Spring_XML_설정_파일_소스에서_구조를_읽는다() {
        Map<String, String> src = new TreeMap<>();
        src.put("pom.xml", """
                <project>
                  <parent>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-parent</artifactId>
                    <version>2.7.18</version>
                  </parent>
                  <dependencies>
                    <dependency><artifactId>mybatis-spring-boot-starter</artifactId></dependency>
                    <dependency><artifactId>spring-boot-starter-aop</artifactId></dependency>
                  </dependencies>
                </project>
                """);
        src.put("src/main/webapp/WEB-INF/web.xml", """
                <web-app>
                  <filter><filter-name>enc</filter-name><filter-class>org.springframework.web.filter.CharacterEncodingFilter</filter-class></filter>
                  <!-- <filter-class>com.old.CommentedFilter</filter-class> -->
                  <session-config><session-timeout>30</session-timeout></session-config>
                </web-app>
                """);
        src.put("src/main/resources/context.xml", """
                <beans>
                  <mvc:interceptors>
                    <bean class="com.x.LoginCheckInterceptor"/>
                  </mvc:interceptors>
                  <bean id="sqlMapClient" class="org.springframework.orm.ibatis.SqlMapClientFactoryBean"/>
                </beans>
                """);
        src.put("src/main/resources/application.yml", """
                spring:
                  session:
                    store-type: redis
                  datasource:
                    password: s3cret
                mybatis:
                  mapper-locations: classpath:mapper/*.xml
                """);
        src.put("src/main/java/com/x/AuthFilter.java", """
                package com.x;
                public class AuthFilter extends OncePerRequestFilter {}
                """);
        src.put("src/main/java/com/x/WebConfig.java", """
                package com.x;
                public class WebConfig implements WebMvcConfigurer {
                    public void addInterceptors(InterceptorRegistry registry) {
                        registry.addInterceptor(new MenuInterceptor());
                    }
                }
                """);

        List<FrameworkFact> facts = FrameworkProfiler.profile(src, JavaSourceIndex.fromSources(src));

        assertThat(facts).extracting(f -> f.kind() + ": " + f.value()).contains(
                "웹: Spring Boot 2.7.18",
                "영속성: MyBatis(Spring Boot)",
                "AOP: Spring AOP(Spring Boot)",
                "필터: CharacterEncodingFilter",
                "세션: web.xml session-config",
                "인터셉터: LoginCheckInterceptor",
                "영속성: iBatis 2",
                "세션: 세션 저장소 redis",
                "설정 파일: application.yml",
                "필터: AuthFilter",
                "인터셉터: MenuInterceptor");
        // 주석 안의 설정은 구조가 아니다. 비밀값은 기록하지 않는다(정해 둔 키만 값을 읽는다).
        assertThat(facts).noneMatch(f -> f.value().contains("CommentedFilter"));
        assertThat(facts).noneMatch(f -> f.value().contains("s3cret") || f.evidence().contains("s3cret"));
        // 근거에 줄 번호를 넣지 않는다 — 코드 몇 줄 바뀐 것으로 trace-rules.yml이 다시 쓰이지 않게.
        assertThat(facts).allMatch(f -> !f.evidence().matches(".*\\.(java|xml|yml):\\d+.*"));
    }

    @Test
    void 같은_저장소면_같은_순서_같은_결과다() {
        Map<String, String> src = new TreeMap<>(Map.of(
                "src/main/java/a/B.java", "package a; @Aspect class B {}",
                "src/main/java/a/A.java", "package a; class A implements HandlerInterceptor {}"));

        List<FrameworkFact> first = FrameworkProfiler.profile(src, JavaSourceIndex.fromSources(src));
        List<FrameworkFact> second = FrameworkProfiler.profile(new TreeMap<>(src), JavaSourceIndex.fromSources(src));

        assertThat(first).isEqualTo(second).hasSize(2);
    }

    @Test
    void XML_AOP_어드바이스는_bean_id를_클래스로_이어_주고_pointcut_ref를_펼친다() {
        Map<String, String> src = new TreeMap<>();
        src.put("beans.xml", "<beans><bean id=\"ua\" class=\"com.x.UserAspect\"/></beans>");
        src.put("aop.xml", """
                <beans>
                  <aop:config>
                    <aop:pointcut id="pc" expression="@annotation(com.x.AddUser) &amp;&amp; args(request,..)"/>
                    <aop:aspect ref="ua"><aop:before method="fill" pointcut-ref="pc"/></aop:aspect>
                    <aop:aspect ref="logAspect"><aop:after method="log" pointcut="execution(* *(..))"/></aop:aspect>
                  </aop:config>
                </beans>
                """);

        List<FrameworkProfiler.XmlAdvice> advices = FrameworkProfiler.xmlAdvices(src);

        // after 어드바이스는 요청 값을 바꾸지 못해(이미 실행된 뒤) 후보가 아니다.
        assertThat(advices).singleElement().satisfies(a -> {
            assertThat(a.aspectClass()).isEqualTo("UserAspect");
            assertThat(a.method()).isEqualTo("fill");
            assertThat(a.pointcut()).isEqualTo("@annotation(com.x.AddUser) && args(request,..)");
            assertThat(a.evidence()).startsWith("aop.xml:4 ");
        });
    }
}
