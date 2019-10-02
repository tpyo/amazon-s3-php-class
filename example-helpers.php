<?php
/**
 * example-helpers.php
 */

/**
 * Get value from environment
 *
 * @param string $name
 * @param string|null $default_value
 * @return string
 */
function _getenv($name, $default_value = null)
{
	$value = getenv($name);
	if ($value !== false) {
		return $value;
	}

	if ($default_value === null) {
		throw new RuntimeException("$name not found in environment");
	}

	return $default_value;
}
