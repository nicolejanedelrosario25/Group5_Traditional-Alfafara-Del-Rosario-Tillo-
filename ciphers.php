<?php
// =========================
// HELPER FUNCTIONS
// =========================
function cleanText($text) {
    return strtoupper(preg_replace('/[^A-Z]/', '', $text));
}

function mod($a, $m) {
    return (($a % $m) + $m) % $m;
}

function gcd($a, $b) {
    while ($b != 0) {
        $temp = $b;
        $b = $a % $b;
        $a = $temp;
    }
    return $a;
}

function modInverse($a, $m) {
    $a = mod($a, $m);
    for ($x = 1; $x < $m; $x++) {
        if (mod($a * $x, $m) == 1) {
            return $x;
        }
    }
    return -1;
}

// =========================
// AFFINE CIPHER
// Formula: E(x) = (ax + b) mod 26
// Formula: D(y) = a^-1(y - b) mod 26
// =========================
function affineEncrypt($plaintext, $a, $b) {
    $plaintext = cleanText($plaintext);

    if (gcd($a, 26) != 1) {
        return "ERROR: Key A must be coprime with 26.";
    }

    $result = "";
    for ($i = 0; $i < strlen($plaintext); $i++) {
        $x = ord($plaintext[$i]) - 65;

        // Affine encryption formula
        $enc = mod(($a * $x + $b), 26);

        $result .= chr($enc + 65);
    }
    return $result;
}

function affineDecrypt($ciphertext, $a, $b) {
    $ciphertext = cleanText($ciphertext);

    if (gcd($a, 26) != 1) {
        return "ERROR: Key A must be coprime with 26.";
    }

    $aInv = modInverse($a, 26);
    if ($aInv == -1) {
        return "ERROR: Modular inverse of Key A does not exist.";
    }

    $result = "";
    for ($i = 0; $i < strlen($ciphertext); $i++) {
        $y = ord($ciphertext[$i]) - 65;

        // Affine decryption formula
        $dec = mod($aInv * ($y - $b), 26);

        $result .= chr($dec + 65);
    }
    return $result;
}

// =========================
// HILL CIPHER 2x2
// Matrix:
// [ a b ]
// [ c d ]
// =========================
function hillPrepareText($text) {
    $text = cleanText($text);

    if (strlen($text) % 2 != 0) {
        $text .= "X";
    }

    return $text;
}

function hillEncrypt($plaintext, $a, $b, $c, $d) {
    $plaintext = hillPrepareText($plaintext);

    $det = mod(($a * $d - $b * $c), 26);
    if (gcd($det, 26) != 1) {
        return "ERROR: Hill key matrix is not invertible mod 26.";
    }

    $result = "";
    for ($i = 0; $i < strlen($plaintext); $i += 2) {
        $x1 = ord($plaintext[$i]) - 65;
        $x2 = ord($plaintext[$i + 1]) - 65;

        // Hill encryption matrix formula
        $y1 = mod(($a * $x1 + $b * $x2), 26);
        $y2 = mod(($c * $x1 + $d * $x2), 26);

        $result .= chr($y1 + 65) . chr($y2 + 65);
    }

    return $result;
}

function hillDecrypt($ciphertext, $a, $b, $c, $d) {
    $ciphertext = hillPrepareText($ciphertext);

    $det = mod(($a * $d - $b * $c), 26);
    if (gcd($det, 26) != 1) {
        return "ERROR: Hill key matrix is not invertible mod 26.";
    }

    $detInv = modInverse($det, 26);
    if ($detInv == -1) {
        return "ERROR: Determinant inverse does not exist.";
    }

    // Inverse matrix formula
    $ia = mod($detInv * $d, 26);
    $ib = mod($detInv * (-$b), 26);
    $ic = mod($detInv * (-$c), 26);
    $id = mod($detInv * $a, 26);

    $result = "";
    for ($i = 0; $i < strlen($ciphertext); $i += 2) {
        $y1 = ord($ciphertext[$i]) - 65;
        $y2 = ord($ciphertext[$i + 1]) - 65;

        $x1 = mod(($ia * $y1 + $ib * $y2), 26);
        $x2 = mod(($ic * $y1 + $id * $y2), 26);

        $result .= chr($x1 + 65) . chr($x2 + 65);
    }

    return $result;
}

// =========================
// PLAYFAIR CIPHER
// Uses 5x5 matrix
// J is replaced with I
// =========================
function generatePlayfairMatrix($key) {
    $key = strtoupper($key);
    $key = preg_replace('/[^A-Z]/', '', $key);
    $key = str_replace('J', 'I', $key);

    $alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
    $used = [];
    $sequence = "";

    for ($i = 0; $i < strlen($key); $i++) {
        $ch = $key[$i];

        if (!isset($used[$ch])) {
            $used[$ch] = true;
            $sequence .= $ch;
        }
    }

    for ($i = 0; $i < strlen($alphabet); $i++) {
        $ch = $alphabet[$i];

        if (!isset($used[$ch])) {
            $used[$ch] = true;
            $sequence .= $ch;
        }
    }

    $matrix = [];
    $positions = [];
    $index = 0;

    for ($r = 0; $r < 5; $r++) {
        for ($c = 0; $c < 5; $c++) {
            $matrix[$r][$c] = $sequence[$index];
            $positions[$sequence[$index]] = [$r, $c];
            $index++;
        }
    }

    return [$matrix, $positions];
}

function preparePlayfairText($text) {
    $text = strtoupper($text);
    $text = preg_replace('/[^A-Z]/', '', $text);
    $text = str_replace('J', 'I', $text);

    $prepared = "";
    $i = 0;

    while ($i < strlen($text)) {
        $a = $text[$i];
        $b = ($i + 1 < strlen($text)) ? $text[$i + 1] : 'X';

        if ($a == $b) {
            $prepared .= $a . 'X';
            $i++;
        } else {
            $prepared .= $a . $b;
            $i += 2;
        }
    }

    if (strlen($prepared) % 2 != 0) {
        $prepared .= 'X';
    }

    return $prepared;
}

function playfairEncrypt($plaintext, $key) {
    list($matrix, $positions) = generatePlayfairMatrix($key);
    $plaintext = preparePlayfairText($plaintext);

    $result = "";

    for ($i = 0; $i < strlen($plaintext); $i += 2) {
        $a = $plaintext[$i];
        $b = $plaintext[$i + 1];

        list($r1, $c1) = $positions[$a];
        list($r2, $c2) = $positions[$b];

        // Rule 1: Same row, move right
        if ($r1 == $r2) {
            $result .= $matrix[$r1][($c1 + 1) % 5];
            $result .= $matrix[$r2][($c2 + 1) % 5];
        }

        // Rule 2: Same column, move down
        elseif ($c1 == $c2) {
            $result .= $matrix[($r1 + 1) % 5][$c1];
            $result .= $matrix[($r2 + 1) % 5][$c2];
        }

        // Rule 3: Rectangle rule
        else {
            $result .= $matrix[$r1][$c2];
            $result .= $matrix[$r2][$c1];
        }
    }

    return $result;
}

function playfairDecrypt($ciphertext, $key) {
    list($matrix, $positions) = generatePlayfairMatrix($key);

    $ciphertext = cleanText($ciphertext);
    $ciphertext = str_replace('J', 'I', $ciphertext);

    if (strlen($ciphertext) % 2 != 0) {
        return "ERROR: Playfair ciphertext must have even number of letters.";
    }

    $result = "";

    for ($i = 0; $i < strlen($ciphertext); $i += 2) {
        $a = $ciphertext[$i];
        $b = $ciphertext[$i + 1];

        list($r1, $c1) = $positions[$a];
        list($r2, $c2) = $positions[$b];

        // Rule 1: Same row, move left
        if ($r1 == $r2) {
            $result .= $matrix[$r1][mod($c1 - 1, 5)];
            $result .= $matrix[$r2][mod($c2 - 1, 5)];
        }

        // Rule 2: Same column, move up
        elseif ($c1 == $c2) {
            $result .= $matrix[mod($r1 - 1, 5)][$c1];
            $result .= $matrix[mod($r2 - 1, 5)][$c2];
        }

        // Rule 3: Rectangle rule
        else {
            $result .= $matrix[$r1][$c2];
            $result .= $matrix[$r2][$c1];
        }
    }

    return $result;
}

// =========================
// FORM PROCESS
// =========================
$selectedCipher = $_POST['cipher'] ?? 'affine';
$mode = $_POST['mode'] ?? 'encrypt';
$inputText = $_POST['inputText'] ?? '';
$outputText = '';

if (isset($_POST['change_cipher'])) {
    $selectedCipher = $_POST['change_cipher'];
    $inputText = '';
    $outputText = '';
    $mode = 'encrypt';
} elseif (isset($_POST['change_mode']) && $_POST['change_mode'] === '1') {
    $inputText = '';
    $outputText = '';
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['process'])) {

    if ($selectedCipher === 'affine') {
        $a = intval($_POST['affine_a'] ?? 5);
        $b = intval($_POST['affine_b'] ?? 8);

        if ($mode === 'encrypt') {
            $outputText = affineEncrypt($inputText, $a, $b);
        } else {
            $outputText = affineDecrypt($inputText, $a, $b);
        }

    } elseif ($selectedCipher === 'hill') {
        $a = intval($_POST['hill_a'] ?? 3);
        $b = intval($_POST['hill_b'] ?? 3);
        $c = intval($_POST['hill_c'] ?? 2);
        $d = intval($_POST['hill_d'] ?? 5);

        if ($mode === 'encrypt') {
            $outputText = hillEncrypt($inputText, $a, $b, $c, $d);
        } else {
            $outputText = hillDecrypt($inputText, $a, $b, $c, $d);
        }

    } elseif ($selectedCipher === 'playfair') {
        $key = $_POST['playfair_key'] ?? 'MONARCHY';

        if ($mode === 'encrypt') {
            $outputText = playfairEncrypt($inputText, $key);
        } else {
            $outputText = playfairDecrypt($inputText, $key);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cipher Toolbox</title>

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: #f7f4f2;
            color: #7f655d;
        }

        .hero {
            text-align: center;
            padding: 85px 20px 140px;
            background: #efe4df;
        }

        .hero h1 {
            font-size: 64px;
            font-weight: 800;
            color: #836c66;
            margin-bottom: 18px;
        }

        .hero p {
            font-size: 18px;
            color: #9a7d72;
        }

        .tool-wrapper {
            max-width: 1150px;
            margin: -60px auto 60px;
            padding: 0 20px;
        }

        .tool-card {
            background: #ffffff;
            border: 2px solid #dcc8bc;
            border-radius: 28px;
            padding: 28px 28px 35px;
            box-shadow: 0 8px 20px rgba(178, 143, 122, 0.10);
        }

        .cipher-tabs {
            display: inline-flex;
            background: #ead8cf;
            border-radius: 999px;
            padding: 5px;
            gap: 5px;
            margin-bottom: 25px;
            flex-wrap: wrap;
        }

        .cipher-tab {
            border: none;
            background: transparent;
            color: #7b6159;
            padding: 10px 24px;
            border-radius: 999px;
            font-size: 16px;
            cursor: pointer;
        }

        .cipher-tab.active {
            background: #ffffff;
            box-shadow: 0 2px 6px rgba(0,0,0,0.10);
            font-weight: 600;
        }

        .mode-row {
            display: flex;
            gap: 20px;
            margin-bottom: 25px;
            margin-top: 5px;
            flex-wrap: wrap;
        }

        .mode-row label {
            font-size: 15px;
            font-weight: 600;
            color: #7c6057;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 22px;
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 10px;
            color: #7c6057;
        }

        textarea,
        input[type="text"],
        input[type="number"] {
            width: 100%;
            padding: 16px;
            border: 1.5px solid #d8c2b6;
            border-radius: 18px;
            outline: none;
            font-size: 16px;
            color: #7b625c;
            background: #fffdfc;
            resize: none;
        }

        textarea:focus,
        input:focus {
            border-color: #c08a6d;
            box-shadow: 0 0 0 3px rgba(192, 138, 109, 0.12);
        }

        .options-area {
            margin-top: 10px;
            margin-bottom: 25px;
        }

        .cipher-options {
            display: none;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 18px;
        }

        .cipher-options.active {
            display: grid;
        }

        .btn {
            background: #be8769;
            color: white;
            border: none;
            border-radius: 999px;
            padding: 15px 40px;
            font-size: 20px;
            font-weight: 600;
            width: 340px;
            max-width: 100%;
            cursor: pointer;
            box-shadow: 0 6px 14px rgba(190, 135, 105, 0.25);
        }

        .btn:hover {
            background: #aa7559;
        }

        .section-title {
            font-size: 18px;
            font-weight: 700;
            color: #876b61;
            margin-bottom: 15px;
        }

        @media (max-width: 850px) {
            .hero h1 {
                font-size: 42px;
            }

            .form-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>

    <section class="hero">
        <h1>Cipher Toolbox</h1>
        <p>Affine, Hill, and Playfair cipher encryption and decryption in one clean interface.</p>
    </section>

    <div class="tool-wrapper">
        <div class="tool-card">

            <form method="POST">

                <div class="cipher-tabs">
                    <button type="submit" name="change_cipher" value="affine" class="cipher-tab <?php echo ($selectedCipher === 'affine') ? 'active' : ''; ?>">
                        Affine Cipher
                    </button>

                    <button type="submit" name="change_cipher" value="hill" class="cipher-tab <?php echo ($selectedCipher === 'hill') ? 'active' : ''; ?>">
                        Hill Cipher
                    </button>

                    <button type="submit" name="change_cipher" value="playfair" class="cipher-tab <?php echo ($selectedCipher === 'playfair') ? 'active' : ''; ?>">
                        Playfair Cipher
                    </button>
                </div>

                <input type="hidden" name="cipher" value="<?php echo htmlspecialchars($selectedCipher); ?>">
                <input type="hidden" name="change_mode" id="change_mode" value="0">

                <div class="mode-row">
                    <label>
                        <input type="radio" name="mode" value="encrypt" <?php echo ($mode === 'encrypt') ? 'checked' : ''; ?> onchange="document.getElementById('change_mode').value='1'; this.form.submit();">
                        Encrypt
                    </label>

                    <label>
                        <input type="radio" name="mode" value="decrypt" <?php echo ($mode === 'decrypt') ? 'checked' : ''; ?> onchange="document.getElementById('change_mode').value='1'; this.form.submit();">
                        Decrypt
                    </label>
                </div>

                <div class="form-grid">
                    <div class="form-group">
                        <label>Input Text</label>
                        <textarea name="inputText" rows="6" placeholder="Enter text here..."><?php echo htmlspecialchars($inputText); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Output Text</label>
                        <textarea rows="6" readonly placeholder="Result will appear here..."><?php echo htmlspecialchars($outputText); ?></textarea>
                    </div>
                </div>

                <div class="options-area">
                    <div class="section-title">Cipher Options</div>

                    <div class="cipher-options <?php echo ($selectedCipher === 'affine') ? 'active' : ''; ?>">
                        <div class="form-group">
                            <label>Key A</label>
                            <input type="number" name="affine_a" value="<?php echo htmlspecialchars($_POST['affine_a'] ?? 5); ?>">
                        </div>

                        <div class="form-group">
                            <label>Key B</label>
                            <input type="number" name="affine_b" value="<?php echo htmlspecialchars($_POST['affine_b'] ?? 8); ?>">
                        </div>
                    </div>

                    <div class="cipher-options <?php echo ($selectedCipher === 'hill') ? 'active' : ''; ?>">
                        <div class="form-group">
                            <label>Matrix A</label>
                            <input type="number" name="hill_a" value="<?php echo htmlspecialchars($_POST['hill_a'] ?? 3); ?>">
                        </div>

                        <div class="form-group">
                            <label>Matrix B</label>
                            <input type="number" name="hill_b" value="<?php echo htmlspecialchars($_POST['hill_b'] ?? 3); ?>">
                        </div>

                        <div class="form-group">
                            <label>Matrix C</label>
                            <input type="number" name="hill_c" value="<?php echo htmlspecialchars($_POST['hill_c'] ?? 2); ?>">
                        </div>

                        <div class="form-group">
                            <label>Matrix D</label>
                            <input type="number" name="hill_d" value="<?php echo htmlspecialchars($_POST['hill_d'] ?? 5); ?>">
                        </div>
                    </div>

                    <div class="cipher-options <?php echo ($selectedCipher === 'playfair') ? 'active' : ''; ?>">
                        <div class="form-group">
                            <label>Keyword</label>
                            <input type="text" name="playfair_key" value="<?php echo htmlspecialchars($_POST['playfair_key'] ?? 'MONARCHY'); ?>">
                        </div>
                    </div>
                </div>

                <button type="submit" name="process" value="1" class="btn">
                    Process
                </button>

            </form>
        </div>
    </div>

</body>
</html>