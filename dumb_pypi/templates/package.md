# {{package_name}}

Latest version: `{{requirement}}`

{% if generate_timestamp %}
Generated on {{date}}.
{% endif %}

## Available Versions

{% for package in packages|reverse %}
- [{{package.version}}]({{package.url}}) ({{package.info_string}})
{% endfor %}
