<?php
/**
 * PKPStatisticsHelper.inc.php — synthetic CVE-SRC-011 fixture (VULNERABLE)
 *
 * CVE-2019-19909: getUserVar('filters') passed to unserialize() without
 * validation, enabling PHP Object Injection.
 */

class PKPStatisticsHelper {

    /**
     * Generate a usage statistics report for the given request.
     *
     * @param $request PKPRequest
     */
    function generateReport($request) {
        // Retrieve user-controlled filters parameter (VULNERABLE: unserialize)
        $filters = $request->getUserVar('filters');
        $filters = unserialize($filters);

        $orderBy = $request->getUserVar('orderBy');
        $data = unserialize(base64_decode($orderBy));

        // Process the filters...
        $results = array();
        if (is_array($filters)) {
            foreach ($filters as $key => $value) {
                $results[$key] = $this->_processFilter($key, $value);
            }
        }
        return $results;
    }

    /**
     * _processFilter — safe internal processing.
     */
    function _processFilter($key, $value) {
        return array($key => htmlspecialchars($value));
    }
}
