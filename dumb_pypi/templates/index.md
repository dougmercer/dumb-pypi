# {{title}}

{% if generate_timestamp %}
Generated on {{date}}.
{% endif %}

## Available Packages

{% for package_name, version in packages %}
- [{{package_name}}]({{package_name}}.md) (latest: {{version}})
{% endfor %}
