# [{{.Filename}}]({{.Path}})
> Date: `{{.Date}}`
> Size: `{{.FileSize}}`
> SHA256: `{{.Sha256}}`

{{ range .Threats }}

## {{.Scanner}}

> {{.Name}}

```nasm
{{.Bytes}}
```

[{{$.Filename}}]({{$.Path}})
{{ if .ReferenceName }}

### Reference

[{{.ReferenceName}}]({{.ReferencePath}})
{{ end }}

---
{{ end }}