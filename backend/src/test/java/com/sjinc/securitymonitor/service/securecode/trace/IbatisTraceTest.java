package com.sjinc.securitymonitor.service.securecode.trace;

import com.sjinc.securitymonitor.dto.securecode.DollarVerdict;
import com.sjinc.securitymonitor.dto.securecode.TraceSafety;
import com.sjinc.securitymonitor.service.securecode.tracerule.TraceRules;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** iBatis 2(sqlMap)의 $값$·#값# — 매퍼 색인과 연계 추적이 MyBatis와 같은 기준으로 판정하는지. 옛 시스템(Spring 어노테이션 없음) 코드 모양으로 본다. */
class IbatisTraceTest {

    private static final String SQLMAP = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE sqlMap PUBLIC "-//ibatis.apache.org//DTD SQL Map 2.0//EN" "http://ibatis.apache.org/dtd/sql-map-2.dtd">
            <sqlMap namespace="Board">
                <select id="list" parameterClass="map" resultClass="hashmap">
                    SELECT * FROM board_$tableSuffix$
                    <dynamic prepend="WHERE">
                        <isNotEmpty prepend="AND" property="compCd">comp_cd = #compCd#</isNotEmpty>
                        <isEqual prepend="AND" property="type" compareValue="notice">kind = '$type$'</isEqual>
                    </dynamic>
                    ORDER BY $sortCol$
                </select>
                <update id="touch" parameterClass="map">
                    UPDATE board <dynamic prepend="SET"><isNotNull prepend="," property="compCd">upd_comp = #compCd:VARCHAR#</isNotNull></dynamic>
                    WHERE id = #id#
                </update>
                <!-- ORDER BY $oldSort$ -->
            </sqlMap>
            """;

    /** Spring 없이 서블릿·옛 프레임워크처럼 request에서 직접 꺼내 맵에 담고 DAO(SqlMapClientTemplate)로 실행하는 코드. */
    private static final String ACTION = """
            package p;
            import java.util.*;
            public class BoardAction {
                private BoardDao dao;
                public Object list(HttpServletRequest request) {
                    Map param = new HashMap();
                    param.put("sortCol", request.getParameter("sort"));
                    param.put("tableSuffix", "2024");
                    param.put("type", request.getParameter("type"));
                    param.put("compCd", request.getParameter("comp"));
                    return dao.list(param);
                }
            }""";

    private static final String DAO = """
            package p;
            import java.util.*;
            public class BoardDao extends SqlMapClientDaoSupport {
                public List list(Map param) {
                    return getSqlMapClientTemplate().queryForList("Board.list", param);
                }
            }""";

    @Test
    void sqlMap의_치환_바인딩_조건자리_상수비교를_읽는다() {
        MapperXmlIndex.MapperFile file = MapperXmlIndex.parse("sqlmap/board.xml", SQLMAP);

        assertThat(file).isNotNull();
        MapperXmlIndex.Statement list = file.statements().get(0);
        assertThat(list.fullId()).isEqualTo("Board.list");
        // 주석 안의 $oldSort$는 없다
        assertThat(list.dollars()).extracting(MapperXmlIndex.Dollar::display).containsExactly("$tableSuffix$", "$type$", "$sortCol$");
        // <isEqual compareValue> 안의 $type$은 XML에서 값이 정해진다
        assertThat(list.dollars().get(1).xmlFixed()).contains("isEqual");
        // <dynamic prepend="WHERE"> 안은 조건, <dynamic prepend="SET"> 안은 값
        assertThat(list.hashes()).extracting(MapperXmlIndex.Dollar::display).containsExactly("#compCd#");
        assertThat(list.hashes().get(0).condition()).isTrue();
        MapperXmlIndex.Statement touch = file.statements().get(1);
        assertThat(touch.hashes()).extracting(h -> h.key() + "=" + h.condition()).containsExactly("compCd=false", "id=true");
        assertThat(touch.hashes().get(0).display()).isEqualTo("#compCd:VARCHAR#");
    }

    @Test
    void namespace가_없는_sqlMap은_id가_전체_id다() {
        MapperXmlIndex.MapperFile file = MapperXmlIndex.parse("a.xml",
                "<sqlMap><select id=\"getUser\">SELECT * FROM u WHERE id = #id#</select></sqlMap>");

        assertThat(file.statements().get(0).fullId()).isEqualTo("getUser");
    }

    @Test
    void SqlMapClientTemplate_실행을_따라가_요청값을_클라이언트_값으로_판정한다() {
        Map<String, String> sources = new LinkedHashMap<>();
        sources.put("src/main/resources/sqlmap/board.xml", SQLMAP);
        sources.put("src/main/java/p/BoardAction.java", ACTION);
        sources.put("src/main/java/p/BoardDao.java", DAO);
        TraceRules rules = new TraceRules(List.of(), Set.of(), Set.of(), Set.of("compCd"));

        MybatisDollarTracer.Result result = MybatisDollarTracer.trace(sources, rules);

        Map<String, DollarVerdict> byDisplay = new LinkedHashMap<>();
        result.verdicts().forEach(v -> byDisplay.put(v.display(), v));
        assertThat(byDisplay.get("$sortCol$").safety()).isEqualTo(TraceSafety.CLIENT);
        assertThat(byDisplay.get("$tableSuffix$").safety()).isEqualTo(TraceSafety.SERVER_SET);
        assertThat(byDisplay.get("$type$").safety()).isEqualTo(TraceSafety.XML_FIXED);
        assertThat(byDisplay.get("$sortCol$").evidence()).last().asString().isEqualTo("board.xml:10 $sortCol$ (Board.list)");
        // 사용자 범위: WHERE 자리의 #compCd#는 클라이언트 값, UPDATE SET 자리는 판정하지 않는다
        assertThat(result.scopeVerdicts()).extracting(DollarVerdict::display, DollarVerdict::safety)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("#compCd#", TraceSafety.CLIENT));
    }
}
