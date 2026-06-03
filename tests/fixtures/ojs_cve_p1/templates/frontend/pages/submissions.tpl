{**
 * submissions.tpl — synthetic CVE-SRC-007 fixture (VULNERABLE)
 *
 * CVE-2023-5903: getLocalizedTitle() used without |escape
 *}
{extends file="layouts/frontend.tpl"}

{block name="content"}
<div class="page page_submissions">
    {foreach from=$sections item=$section}
    <div class="section">
        <h2>
            {translate
                key="submission.section"
                name=$section->getLocalizedTitle()
            }
        </h2>
        <ul>
            {foreach from=$section.submissions item=$submission}
            <li>{$submission->getLocalizedTitle()|escape}</li>
            {/foreach}
        </ul>
    </div>
    {/foreach}
</div>
{/block}
