{**
 * search.tpl — synthetic CVE-SRC-012 fixture (OJS 2.x path, VULNERABLE)
 *
 * CVE-2018-12229: {$authors} reflected in value attribute without |escape
 *}
{assign var="pageTitle" value="search.searchJournal"}
{include file="common/header.tpl"}

<div id="searchContents">
<form method="get" action="{url page="search" op="search"}" id="searchForm">
    <table>
        <tr>
            <td><label for="query">{translate key="search.searchFor"}</label></td>
            <td><input type="text" id="query" name="query" size="40" value="{$query|escape}"></td>
        </tr>
        <tr>
            <td><label for="authors">{translate key="search.author"}</label></td>
            <td><input type="text" id="authors" name="authors" size="40" value="{$authors}"></td>
        </tr>
        <tr>
            <td><label for="title">{translate key="search.title"}</label></td>
            <td><input type="text" id="title" name="title" size="40" value="{$title|escape}"></td>
        </tr>
    </table>
    <input type="submit" value="{translate key="common.search"}" class="button defaultButton">
</form>
</div>

{include file="common/footer.tpl"}
