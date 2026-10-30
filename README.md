# Apache WSS4J 2.1.x — Tomitribe maintenance branch

This branch carries Tomitribe maintenance releases of Apache WSS4J 2.1.12 for Apache TomEE 7.1,
which runs on Apache CXF 3.1.x and so needs the WSS4J 2.1 API. Upstream no longer maintains the
2.1.x line.

- **Base:** created from the upstream release tag `wss4j-2.1.12`
  (commit `f4248b28b4d75a66e7bde212ec13c299069364b6`).
- **Versions:** `2.1.12-TT.N`. The Maven `groupId` stays `org.apache.wss4j`, and the artifact IDs
  are unchanged.
- **Changes:** security fixes backported from later upstream releases. Each commit names the
  upstream commit it backports.
- **Build:** JDK 8 with Java 7 source/target level (`targetJdk` 1.7), as upstream 2.1.12.

For the upstream project description, see [README.txt](README.txt) and
http://ws.apache.org/wss4j/.
