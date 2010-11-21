<?xml version="1.0"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/clusters">
		<html>
			<head><title>Groups of potentially correlated alerts</title></head>
			<body>
				<h1>Alert clusters from the <i>SOM</i> neural network</h1>
				<ul>
					<xsl:apply-templates select="cluster">
						<xsl:sort select="id"/>
					</xsl:apply-templates>
				</ul>
			</body>
		</html>
	</xsl:template>

	<xsl:template match="cluster">
		<li>
			<i><xsl:text>Alert cluster </xsl:text>
			<xsl:value-of select="@id"/></i>
		</li>

		<ul>
			<xsl:apply-templates select="alert">
				<xsl:sort select="gid"/>
			</xsl:apply-templates>
		</ul><br/>
	</xsl:template>

	<xsl:template match="alert">
		<li>
			<b><xsl:value-of select="@desc"/></b>
			<xsl:text>received at </xsl:text>
			<u><xsl:value-of select="@timestamp"/></u>
			<xsl:text>, </xsl:text>
			<i><xsl:value-of select="@src_ip"/>
			<xsl:text>:</xsl:text>
			<xsl:value-of select="@src_port"/>
			<xsl:text> -> </xsl:text>
			<xsl:value-of select="@dst_ip"/>
			<xsl:text>:</xsl:text>
			<xsl:value-of select="@dst_port"/></i>
		</li>
	</xsl:template>
</xsl:stylesheet>

