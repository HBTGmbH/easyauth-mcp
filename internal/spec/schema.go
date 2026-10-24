package spec

import (
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

var skippedHeaders = map[string]struct{}{
	"authorization":            {},
	"accept":                   {},
	"content-type":             {},
	"x-ms-client-principal-id": {},
}

// buildInputSchema merges path, query and header parameters plus the JSON
// request body into a single flat object schema. The returned map associates
// every included property with its parameter location.
func buildInputSchema(operation *openapi3.Operation, pathItem *openapi3.PathItem) (map[string]any, map[string]string) {
	properties := make(map[string]any)
	paramIn := make(map[string]string)
	var required []string

	parameters := mergeParameters(pathItem.Parameters, operation.Parameters)
	for _, in := range []string{openapi3.ParameterInPath, openapi3.ParameterInQuery, openapi3.ParameterInHeader} {
		for _, ref := range parameters {
			if ref == nil || ref.Value == nil {
				continue
			}
			param := ref.Value
			if param.In != in {
				continue
			}
			if strings.EqualFold(param.Name, "csv") {
				continue
			}
			if in == openapi3.ParameterInHeader {
				if _, skip := skippedHeaders[strings.ToLower(param.Name)]; skip {
					continue
				}
			}
			if _, exists := properties[param.Name]; exists {
				continue
			}
			properties[param.Name] = convertSchemaRef(param.Schema)
			paramIn[param.Name] = in
			if param.Required {
				required = append(required, param.Name)
			}
		}
	}

	addRequestBody(operation.RequestBody, properties, paramIn, &required)

	schema := map[string]any{"type": "object"}
	if len(properties) > 0 {
		schema["properties"] = properties
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema, paramIn
}

// mergeParameters combines path-level and operation-level parameters by
// (in, name); operation-level definitions win.
func mergeParameters(pathParams, opParams openapi3.Parameters) openapi3.Parameters {
	merged := make(openapi3.Parameters, 0, len(pathParams)+len(opParams))
	seen := make(map[string]struct{})
	for _, ref := range append(append(openapi3.Parameters{}, pathParams...), opParams...) {
		if ref == nil || ref.Value == nil {
			continue
		}
		key := ref.Value.In + "\x00" + ref.Value.Name
		if _, exists := seen[key]; exists {
			for i := range merged {
				if merged[i].Value != nil && merged[i].Value.In == ref.Value.In && merged[i].Value.Name == ref.Value.Name {
					merged[i] = ref
					break
				}
			}
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, ref)
	}
	return merged
}

func addRequestBody(ref *openapi3.RequestBodyRef, properties map[string]any, paramIn map[string]string, required *[]string) {
	if ref == nil || ref.Value == nil {
		return
	}
	mediaType, ok := ref.Value.Content["application/json"]
	if !ok || mediaType == nil || mediaType.Schema == nil || mediaType.Schema.Value == nil {
		return
	}
	bodySchema := mediaType.Schema.Value
	for name, propRef := range bodySchema.Properties {
		propertyName := name
		if _, collision := properties[propertyName]; collision {
			propertyName = "body_" + name
		}
		properties[propertyName] = convertSchemaRef(propRef)
		paramIn[propertyName] = "body"
		if slices.Contains(bodySchema.Required, name) {
			*required = append(*required, propertyName)
		}
	}
}

func convertSchemaRef(ref *openapi3.SchemaRef) map[string]any {
	if ref == nil || ref.Value == nil {
		return map[string]any{}
	}
	return convertSchema(ref.Value, make(map[*openapi3.Schema]struct{}))
}

func convertSchema(schema *openapi3.Schema, visiting map[*openapi3.Schema]struct{}) map[string]any {
	if schema == nil {
		return map[string]any{}
	}
	if _, cycle := visiting[schema]; cycle {
		if t := schemaType(schema); t != "" {
			return map[string]any{"type": t}
		}
		return map[string]any{"type": "object"}
	}
	visiting[schema] = struct{}{}
	defer delete(visiting, schema)

	out := make(map[string]any)

	if t := schemaType(schema); t != "" {
		out["type"] = t
	}
	if schema.Format != "" {
		out["format"] = schema.Format
	}
	if schema.Description != "" {
		out["description"] = schema.Description
	}
	if len(schema.Enum) > 0 {
		out["enum"] = schema.Enum
	}
	if schema.Default != nil {
		out["default"] = schema.Default
	}
	if schema.Min != nil {
		out["minimum"] = *schema.Min
	}
	if schema.Max != nil {
		out["maximum"] = *schema.Max
	}
	if schema.MinLength > 0 {
		out["minLength"] = schema.MinLength
	}
	if schema.MaxLength != nil {
		out["maxLength"] = *schema.MaxLength
	}
	if schema.Pattern != "" {
		out["pattern"] = schema.Pattern
	}
	if schema.Items != nil {
		out["items"] = convertSchemaRefIn(schema.Items, visiting)
	}
	if len(schema.Properties) > 0 {
		props := make(map[string]any, len(schema.Properties))
		for name, propRef := range schema.Properties {
			props[name] = convertSchemaRefIn(propRef, visiting)
		}
		out["properties"] = props
	}
	if len(schema.Required) > 0 {
		out["required"] = schema.Required
	}
	if schema.AdditionalProperties.Has != nil {
		out["additionalProperties"] = *schema.AdditionalProperties.Has
	}

	return out
}

func convertSchemaRefIn(ref *openapi3.SchemaRef, visiting map[*openapi3.Schema]struct{}) map[string]any {
	if ref == nil || ref.Value == nil {
		return map[string]any{}
	}
	return convertSchema(ref.Value, visiting)
}

func schemaType(schema *openapi3.Schema) string {
	if schema.Type == nil || schema.Type.IsEmpty() {
		if len(schema.Properties) > 0 {
			return "object"
		}
		return ""
	}
	return strings.Join(schema.Type.Slice(), ",")
}
