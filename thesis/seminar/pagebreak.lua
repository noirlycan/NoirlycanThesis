function RawBlock(el)
  if el.format == "tex" and el.text:match("\\newpage") then
    return pandoc.RawBlock(
      "openxml",
      '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'
    )
  end
end
