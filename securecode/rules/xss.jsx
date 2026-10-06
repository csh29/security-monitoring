export function Notice({ notice }) {
  // ruleid: kisa-xss-framework-raw-html
  const raw = <div dangerouslySetInnerHTML={{ __html: notice.content }} />;
  // ok: kisa-xss-framework-raw-html
  const safe = <div>{notice.content}</div>;
  return <div>{raw}{safe}</div>;
}
