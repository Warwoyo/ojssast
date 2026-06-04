<?php
/**
 * PKPToolsHandler.inc.php — synthetic CVE-SRC-011 fixture (OJS 2.x/manager path, VULNERABLE)
 *
 * CVE-2019-19909: getUserVar('filters') passed to unserialize() without
 * validation, enabling PHP Object Injection.
 */

class PKPToolsHandler extends Handler {

    /**
     * Execute a report generation request.
     */
    function execute($args, $request) {
        // Retrieve user-controlled filters parameter (VULNERABLE: unserialize)
        $filters = $request->getUserVar('filters');
        $filters = unserialize($filters);

        $orderBy = $request->getUserVar('orderBy');
        $data = unserialize(base64_decode($orderBy));

        // Process the report...
        $results = array();
        if (is_array($filters)) {
            foreach ($filters as $key => $value) {
                $results[$key] = $value;
            }
        }
        return $results;
    }

    /**
     * Render tools page.
     */
    function index($args, $request) {
        $templateMgr = TemplateManager::getManager($request);
        $templateMgr->display('manager/tools/index.tpl');
    }
}
