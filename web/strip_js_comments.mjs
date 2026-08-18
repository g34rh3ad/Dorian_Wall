import { readFileSync, writeFileSync } from "fs";
import * as acorn from "acorn";

const files = process.argv.slice(2);

for (const file of files) {
  const src = readFileSync(file, "utf8");
  const comments = [];
  try {
    acorn.parse(src, {
      ecmaVersion: "latest",
      sourceType: "module",
      onComment: comments,
    });
  } catch (e) {
    console.error(`SKIP (parse error) ${file}: ${e.message}`);
    continue;
  }

  comments.sort((a, b) => b.start - a.start);
  let out = src;
  for (const c of comments) {
    out = out.slice(0, c.start) + out.slice(c.end);
  }

  const lines = out.split("\n").map((l) => l.replace(/[ \t]+$/, ""));
  const collapsed = [];
  let blankRun = 0;
  for (const ln of lines) {
    if (ln.trim() === "") {
      blankRun++;
      if (blankRun > 2) continue;
    } else {
      blankRun = 0;
    }
    collapsed.push(ln);
  }
  let final = collapsed.join("\n");
  if (!final.endsWith("\n")) final += "\n";

  try {
    acorn.parse(final, { ecmaVersion: "latest", sourceType: "module" });
  } catch (e) {
    console.error(`FINAL PARSE ERROR ${file}: ${e.message}`);
    writeFileSync(file + ".broken", final);
    continue;
  }

  writeFileSync(file, final);
  console.log(`OK ${file}`);
}
