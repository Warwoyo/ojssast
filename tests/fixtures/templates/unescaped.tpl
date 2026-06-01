{* article display template *}
<h1>{$article->getLocalizedTitle()}</h1>      {* RULE-SRC-001: unescaped *}
<div class="abstract">{$abstract}</div>        {* RULE-SRC-001: unescaped *}
<p>Author: {$authorName|escape}</p>            {* safe: escaped *}
<a href="{$downloadUrl|escape:"url"}">PDF</a>  {* safe: escaped *}
<span>{$smarty.now|date_format}</span>          {* safe: reserved/modifier *}
