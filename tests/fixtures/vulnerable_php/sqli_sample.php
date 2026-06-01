<?php
/**
 * SQL injection sample (CWE-89) via DB::raw / Capsule::raw concatenation.
 */
class SubmissionSearchDAO extends DAO {
	function getByTitle($request) {
		$title = $request->getUserVar('title');                       // tainted
		$rows = DB::raw("SELECT * FROM submissions WHERE title = '" . $title . "'");  // RULE-SRC-005

		$sql = "SELECT * FROM authors WHERE id = " . $_GET['id'];     // tainted via concat
		Capsule::raw($sql);                                           // RULE-SRC-005 (taint)

		// Safe: parameter binding must NOT be flagged.
		$safe = Capsule::table('users')->where('id', '=', (int) $_GET['id'])->get();
		return $rows;
	}
}
