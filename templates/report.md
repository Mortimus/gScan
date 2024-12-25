# [{{.Filename}}]({{.Path}})
{{ range .Threats }}

## {{.Scanner}}

> {{.Name}}

```nasm
{{.Bytes}}
```

{{ if .Reference }}
### Reference

```yaml
{{.Reference}}
```

^{{.ReferencePath}}^
{{ end }}

---
{{ end }}