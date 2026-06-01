<?php
/**
 * Reflected XSS sample (CWE-79). OJS-flavored handler.
 */
import('classes.handler.Handler');

class IssueHandler extends Handler {
	function view($args, $request) {
		$searchQuery = $request->getUserVar('query');         // tainted source
		echo "<h2>Search results for: " . $searchQuery . "</h2>";  // RULE-SRC-007 (XSS)
		printf("<p>%s</p>", $_GET['note']);                   // RULE-SRC-007 (XSS)

		// Safe: sanitized output must NOT be flagged.
		$safe = PKPString::htmlspecialchars($request->getUserVar('safe'));
		echo $safe;
		$id = (int) $request->getUserVar('id');
		echo $id;
	}
}
