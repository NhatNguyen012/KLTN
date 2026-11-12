// Thư viện nhỏ dựng file Word (docx-js) cho hai tài liệu mô tả dataset.
const d = require("docx");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType, BorderStyle,
  WidthType, ShadingType, LevelFormat, Footer, PageNumber, TabStopType, ImageRun,
} = d;

const FONT = "Arial";
const W = 9638; // chiều rộng nội dung (A4, lề 2 cm) tính bằng DXA

function runs(text, base = {}) {
  // **đậm** (có thể chứa `mã`) và `mã`
  const out = [];
  const re = /(\*\*.+?\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(new TextRun({ text: text.slice(last, m.index), font: FONT, ...base }));
    const tok = m[0];
    if (tok.startsWith("**")) out.push(...runs(tok.slice(2, -2), { ...base, bold: true }));
    else out.push(new TextRun({ text: tok.slice(1, -1), font: "Consolas", size: (base.size || 22) - 2, color: base.color, bold: base.bold }));
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(new TextRun({ text: text.slice(last), font: FONT, ...base }));
  return out;
}

const P = (text, o = {}) => new Paragraph({ spacing: { after: 100, line: 276 }, alignment: o.align, children: runs(text, { size: o.size || 22, color: o.color, italics: o.italics }) });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 140 }, children: [new TextRun({ text: t, font: FONT, bold: true, size: 30, color: "1F3864" })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 220, after: 100 }, children: [new TextRun({ text: t, font: FONT, bold: true, size: 25, color: "2F5597" })] });
const B = (t, lvl = 0) => new Paragraph({ numbering: { reference: "bul", level: lvl }, spacing: { after: 60, line: 264 }, children: runs(t, { size: 22 }) });
const NOTE = (t, fill = "FFF4CE") => new Paragraph({
  spacing: { before: 80, after: 120, line: 264 },
  shading: { type: ShadingType.CLEAR, fill },
  border: { left: { style: BorderStyle.SINGLE, size: 18, color: "BF9000", space: 6 } },
  indent: { left: 140 },
  children: runs(t, { size: 21 }),
});

const thin = { style: BorderStyle.SINGLE, size: 4, color: "A6A6A6" };
const borders = { top: thin, bottom: thin, left: thin, right: thin };

function T(headers, rows, widths, o = {}) {
  const sum = widths.reduce((a, b) => a + b, 0);
  const fs = o.size || 18;
  const cell = (txt, w, hdr, fill) => new TableCell({
    width: { size: w, type: WidthType.DXA }, borders,
    shading: hdr ? { type: ShadingType.CLEAR, fill: "D9E2F3" } : (fill ? { type: ShadingType.CLEAR, fill } : undefined),
    margins: { top: 50, bottom: 50, left: 80, right: 80 },
    children: String(txt).split("\n").map((line) => new Paragraph({ spacing: { after: 20 }, children: runs(line, { size: fs, bold: hdr || undefined }) })),
  });
  const trs = [new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, widths[i], true)) })];
  rows.forEach((r) => trs.push(new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, widths[i], false, o.firstColFill && i === 0 ? "F2F2F2" : null)) })));
  return new Table({ width: { size: sum, type: WidthType.DXA }, columnWidths: widths, rows: trs });
}


const CODE = (lines, o = {}) => (Array.isArray(lines) ? lines : String(lines).split("\n")).map((ln, i, arr) => new Paragraph({
  spacing: { after: i === arr.length - 1 ? 120 : 0, line: 240 },
  shading: { type: ShadingType.CLEAR, fill: "F2F2F2" },
  indent: { left: 100, right: 100 },
  children: [new TextRun({ text: ln === "" ? " " : ln, font: "Consolas", size: o.size || 16 })],
}));

const IMG = (file, wpx, hpx) => new Paragraph({
  alignment: AlignmentType.CENTER, spacing: { before: 60, after: 120 },
  children: [new ImageRun({ type: "png", data: require("fs").readFileSync(file), transformation: { width: wpx, height: hpx }, altText: { title: "so do", description: "so do", name: "so do" } })],
});

const SP = () => new Paragraph({ spacing: { after: 80 }, children: [] });

function build(title, subtitle, children, file) {
  const doc = new Document({
    creator: "KLTN Network DL",
    title,
    styles: { default: { document: { run: { font: FONT, size: 22 } } } },
    numbering: { config: [{ reference: "bul", levels: [
      { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } },
      { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1000, hanging: 270 } } } },
    ] }] },
    sections: [{
      properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: title + " – trang ", font: FONT, size: 16, color: "7F7F7F" }), new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 16, color: "7F7F7F" })] })] }) },
      children: [
        new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: title, font: FONT, bold: true, size: 40, color: "1F3864" })] }),
        new Paragraph({ spacing: { after: 200 }, border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: "2F5597", space: 4 } }, children: [new TextRun({ text: subtitle, font: FONT, size: 22, color: "595959" })] }),
        ...children,
      ],
    }],
  });
  return Packer.toBuffer(doc).then((buf) => require("fs").writeFileSync(file, buf));
}

module.exports = { P, H1, H2, B, NOTE, T, SP, CODE, IMG, build, W };
