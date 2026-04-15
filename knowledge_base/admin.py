from django.contrib import admin

from .models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, ReferenceLink, RemediationTemplate, VulnerabilityRule


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor')
    search_fields = ('name', 'vendor')


@admin.register(ProductAlias)
class ProductAliasAdmin(admin.ModelAdmin):
    list_display = ('alias', 'product')
    search_fields = ('alias', 'product__name')
    list_select_related = ('product',)


@admin.register(RemediationTemplate)
class RemediationTemplateAdmin(admin.ModelAdmin):
    list_display = ('title',)
    search_fields = ('title',)


class BaseRuleAdmin(admin.ModelAdmin):
    list_display = ('title', 'product', 'severity', 'confidence', 'port', 'protocol')
    list_filter = ('severity', 'confidence', 'protocol')
    search_fields = ('title', 'description', 'product__name')
    list_select_related = ('product', 'remediation_template')


@admin.register(VulnerabilityRule)
class VulnerabilityRuleAdmin(BaseRuleAdmin):
    pass


@admin.register(MisconfigurationRule)
class MisconfigurationRuleAdmin(BaseRuleAdmin):
    pass


@admin.register(EndOfLifeRule)
class EndOfLifeRuleAdmin(BaseRuleAdmin):
    list_display = BaseRuleAdmin.list_display + ('eol_date',)


@admin.register(ReferenceLink)
class ReferenceLinkAdmin(admin.ModelAdmin):
    list_display = ('label', 'url', 'vulnerability_rule', 'misconfiguration_rule', 'end_of_life_rule')
    search_fields = ('label', 'url')
