"""release_notes.py의 순수 함수 테스트(네트워크 없음). 실행: ai 폴더에서 `py -m unittest test_release_notes`."""

import unittest

import release_notes as rn


def v(text):
    return rn.parse_version(text)[0]


class ParseVersionTest(unittest.TestCase):
    def test_태그_접두사와_접미사를_떼고_읽는다(self):
        self.assertEqual(rn.parse_version("v3.2.1"), ((3, 2, 1), ""))
        self.assertEqual(rn.parse_version("jackson-databind-2.16.1"), ((2, 16, 1), ""))
        self.assertEqual(rn.parse_version("netty-4.1.118.Final"), ((4, 1, 118), "final"))
        self.assertEqual(rn.parse_version("# 2024-12-09 Tomcat 10.1.34 (schultz)"), ((10, 1, 34), ""))
        self.assertEqual(rn.parse_version("3.2.0-M1"), ((3, 2, 0), "m"))

    def test_버전이_없으면_None(self):
        self.assertIsNone(rn.parse_version("Bug Fixes"))
        self.assertIsNone(rn.parse_version("2024-12-09"))


class RangeTest(unittest.TestCase):
    def test_옛_라인의_뒤늦은_패치는_범위에서_뺀다(self):
        self.assertTrue(rn.in_upgrade_range(v("3.2.0"), v("3.1.5"), v("3.2.12")))
        self.assertTrue(rn.in_upgrade_range(v("3.2.12"), v("3.1.5"), v("3.2.12")))
        self.assertFalse(rn.in_upgrade_range(v("3.1.6"), v("3.1.5"), v("3.2.12")))
        self.assertFalse(rn.in_upgrade_range(v("3.2.13"), v("3.1.5"), v("3.2.12")))
        self.assertFalse(rn.in_upgrade_range(v("3.1.5"), v("3.1.5"), v("3.2.12")))

    def test_같은_라인이면_범위만_본다(self):
        self.assertTrue(rn.in_upgrade_range(v("10.1.20"), v("10.1.16"), v("10.1.34")))

    def test_새_라인_x_y_0_사전_릴리스만_넣는다(self):
        self.assertTrue(rn.is_relevant_release(rn.parse_version("10.1.0-M1"), v("10.0.27"), v("10.1.34")))
        self.assertFalse(rn.is_relevant_release(rn.parse_version("10.1.35-RC1"), v("10.0.27"), v("10.1.34")))
        # 같은 라인 안의 업그레이드에는 사전 릴리스를 넣지 않는다.
        self.assertFalse(rn.is_relevant_release(rn.parse_version("10.1.0-M1"), v("10.1.0"), v("10.1.34")))

    def test_지나가는_라인_목록(self):
        self.assertEqual(rn.lines_between(v("3.1.5"), v("3.3.1")), ["3.2", "3.3"])
        self.assertEqual(rn.lines_between(v("3.2.1"), v("3.2.12")), [])
        lines = rn.lines_between(v("2.7.18"), v("3.1.0"))
        self.assertIn("3.0", lines)
        self.assertIn("3.1", lines)
        self.assertNotIn("2.7", lines)


class SliceTest(unittest.TestCase):
    CHANGELOG = """# Changelog

## 2.3.0
### Features
- New API
### Breaking
- Removed Foo (was deprecated since 1.9.0)

## 2.2.1
- Bump bar to 1.2.3

## 2.2.0
- Old stuff
"""

    def test_버전_없는_소제목은_절을_끊지_않는다(self):
        sliced = rn.slice_by_version_headings(self.CHANGELOG, v("2.2.1"), v("2.3.0"))
        self.assertIn("Removed Foo", sliced)
        self.assertIn("New API", sliced)
        self.assertNotIn("Bump bar", sliced)
        self.assertNotIn("Old stuff", sliced)

    def test_목록_항목의_버전은_제목이_아니다(self):
        sliced = rn.slice_by_version_headings(self.CHANGELOG, v("2.2.0"), v("2.2.1"))
        self.assertIn("Bump bar", sliced)
        self.assertNotIn("Old stuff", sliced)

    def test_새_라인의_x_y_0_절을_앞에_둔다(self):
        text = "# Tomcat 10.1.34\n- patch fix\n\n# Tomcat 10.1.0-M1\n- removed old API\n"
        sliced = rn.slice_by_version_headings(text, v("10.0.27"), v("10.1.34"))
        self.assertLess(sliced.index("removed old API"), sliced.index("patch fix"))

    def test_범위_안_절이_없으면_None(self):
        self.assertIsNone(rn.slice_by_version_headings(self.CHANGELOG, v("3.0.0"), v("3.1.0")))


class HtmlTest(unittest.TestCase):
    def test_컨테이너_안_본문만_읽는다(self):
        html = """<html><body><nav>메뉴</nav><div class="side">사이드바</div>
        <div id="wiki-body"><h2>Upgrading</h2><div><p>Removed <code>Foo</code>.</p></div></div>
        <div>푸터 문구</div></body></html>"""
        text = rn.html_to_text(html, "wiki-body")
        self.assertIn("# Upgrading", text)
        self.assertIn("Removed Foo.", text)
        self.assertNotIn("사이드바", text)
        self.assertNotIn("푸터", text)

    def test_스크립트와_스타일은_버린다(self):
        text = rn.html_to_text("<p>본문</p><script>var x=1;</script><style>p{}</style>")
        self.assertEqual(text, "본문")


class ScmTest(unittest.TestCase):
    def test_여러_형태의_GitHub_scm_주소(self):
        for url in ["https://github.com/netty/netty", "scm:git:git://github.com/netty/netty.git",
                    "git@github.com:netty/netty.git", "scm:git:https://github.com/netty/netty.git/tree/4.1"]:
            self.assertEqual(rn.parse_github_repo(url), ("netty", "netty"), url)
        self.assertIsNone(rn.parse_github_repo("https://gitbox.apache.org/repos/asf/kafka.git"))


class _FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = {}

    def json(self):
        import json
        return json.loads(self.text)


class _FakeSession:
    """주소별 응답을 돌려주고, 불린 주소를 기록한다. 등록 안 된 주소는 404."""

    def __init__(self, pages):
        self.pages = pages
        self.headers = {}
        self.requested = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.requested.append(url)
        return _FakeResponse(200, self.pages[url]) if url in self.pages else _FakeResponse(404)


class CollectTest(unittest.TestCase):
    WIKI = "https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-3.2-Release-Notes"

    def test_공식_문서가_있으면_저장소_릴리스_노트를_부르지_않는다(self):
        session = _FakeSession({self.WIKI: '<div id="wiki-body"><h2>Upgrading</h2><p>Removed Foo.</p></div>'})

        result = rn.collect("org.springframework.boot:spring-boot-starter-parent", "3.1.5", "3.2.12", session)

        self.assertEqual([d.url for d in result.documents], [self.WIKI])
        self.assertFalse(any("api.github.com" in u or "repo1.maven.org" in u for u in session.requested))
        self.assertTrue(any("패치 노트" in n for n in result.notes))

    def test_공식_문서가_없으면_POM의_scm을_따라간다(self):
        pom = ("<project xmlns='http://maven.apache.org/POM/4.0.0'>"
               "<scm><url>https://github.com/acme/lib</url></scm></project>")
        releases = '[{"tag_name": "v1.3.0", "name": "1.3.0", "body": "Removed old API", ' \
                   '"html_url": "https://github.com/acme/lib/releases/tag/v1.3.0", "draft": false, "prerelease": false}]'
        session = _FakeSession({
            "https://repo1.maven.org/maven2/com/acme/lib/1.3.0/lib-1.3.0.pom": pom,
            "https://api.github.com/repos/acme/lib/releases": releases,
        })

        result = rn.collect("com.acme:lib", "1.2.0", "1.3.0", session)

        self.assertEqual([d.kind for d in result.documents], ["GITHUB_RELEASE"])
        self.assertIn("Removed old API", result.documents[0].text)


class BudgetTest(unittest.TestCase):
    def test_총량을_넘으면_뒤쪽_문서부터_빼고_메모를_남긴다(self):
        result = rn.CollectionResult(documents=[
            rn.ReleaseDocument("OFFICIAL_DOC", "https://a", "가이드", "x" * (rn.MAX_TOTAL_CHARS - 10)),
            rn.ReleaseDocument("GITHUB_RELEASE", "https://b", "v1", "y" * 100),
        ])
        rn._fit_budget(result)
        self.assertEqual([d.url for d in result.documents], ["https://a"])
        self.assertTrue(any("1건" in n for n in result.notes))


if __name__ == "__main__":
    unittest.main()
