<?php
echo "<pre>";

echo "Checking /data directory...\n";
echo is_dir('/data') ? "/data exists.\n" : "/data does NOT exist.\n";

echo "\nChecking writability BEFORE chmod:\n";
echo is_writable('/data') ? "/data is writable.\n" : "/data is NOT writable.\n";

@chmod('/data', 0777);

echo "\nChecking writability AFTER chmod:\n";
echo is_writable('/data') ? "/data is writable.\n" : "/data is NOT writable.\n";

echo "\nAttempting to write to /data...\n";
$testFile = '/data/volume_test.txt';
$result = @file_put_contents($testFile, "Volume test at " . date('Y-m-d H:i:s'));

echo $result !== false
    ? "Write SUCCESSFUL! File created: $testFile\n"
    : "Write FAILED.\n";

echo "\nListing /data contents:\n";
@system('ls -lah /data');

echo "</pre>";
