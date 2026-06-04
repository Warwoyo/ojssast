{**
 * search.tpl — realistic CVE-SRC-012 fixture with mixed safe/unsafe expressions.
 *
 * Some fields use |escape (safe), but {$authors} in value attribute does NOT.
 * A file-level check for "$authors|escape" must NOT suppress this finding,
 * because the escaped usage is in a display context (not the value attribute).
 *}
{extends file="layouts/frontend.tpl"}

{block name="content"}
<div class="page page_search">
    <h1>{$pageTitle|escape}</h1>

    {* Display the current author search term safely in a paragraph *}
    {if $authors}
        <p class="active-filter">{translate key="search.filterAuthor"}: {$authors|escape}</p>
    {/if}

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
