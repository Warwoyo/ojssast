{**
 * search.tpl — synthetic CVE-SRC-012 fixture (VULNERABLE)
 *
 * CVE-2018-12229: {$authors} reflected in value attribute without |escape
 *}
{extends file="layouts/frontend.tpl"}

{block name="content"}
<div class="page page_search">
    <form method="get" action="{url router=$smarty.const.ROUTE_PAGE page="search"}">
        <div class="search_field">
            <label for="query">{translate key="search.searchFor"}</label>
            <input type="text" id="query" name="query" value="{$query|escape}">
        </div>
        <div class="search_field">
            <label for="authors">{translate key="search.author"}</label>
            <input
                type="text"
                id="authors"
                name="authors"
                value="{$authors}"
            >
        </div>
        <div class="search_field">
            <label for="title">{translate key="search.title"}</label>
            <input type="text" name="title" value="{$title|escape}">
        </div>
        <input type="submit" value="{translate key="common.search"}">
    </form>
</div>
{/block}
