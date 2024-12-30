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

{{ if .PeData }}
## PE Data

> Signed: {{.PeData.IsSigned}}
> IAT: {{.PeData.HasIAT}}
> Delayed Imports: {{.PeData.HasDelayImp}}

### Import Address Table (IAT)

```json
{{range .PeData.IAT}}
{{.Meaning}}
{{end}}
```

### Delayed Imports

```json
{{range .PeData.DelayImports}}
{{.Name}}
{{end}}
```

{{end}}