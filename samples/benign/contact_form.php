<?php
/*
 * contact_form.php — a genuinely benign, legitimate web page.
 *
 * A normal contact form: validates input, escapes output, stores nothing
 * dangerous. It performs only input validation and HTML escaping — there is no
 * command or code execution and no obfuscation, exactly the kind of legitimate
 * PHP that a web-shell heuristic must not flag.
 */
declare(strict_types=1);

function clean(string $v): string
{
    return htmlspecialchars(trim($v), ENT_QUOTES, 'UTF-8');
}

$errors = [];
$sent = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name    = clean($_POST['name'] ?? '');
    $email   = clean($_POST['email'] ?? '');
    $message = clean($_POST['message'] ?? '');

    if ($name === '') {
        $errors[] = 'Please enter your name.';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }
    if (strlen($message) < 10) {
        $errors[] = 'Your message is a little short.';
    }

    if (!$errors) {
        // In a real app this would persist via a prepared statement, e.g.:
        //   $stmt = $pdo->prepare('INSERT INTO messages (name,email,body) VALUES (?,?,?)');
        //   $stmt->execute([$name, $email, $message]);
        $sent = true;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Contact us</title></head>
<body>
  <h1>Contact us</h1>
  <?php if ($sent): ?>
    <p>Thanks, <?= $name ?> — we'll get back to you at <?= $email ?>.</p>
  <?php else: ?>
    <?php foreach ($errors as $e): ?>
      <p class="error"><?= $e ?></p>
    <?php endforeach; ?>
    <form method="post" action="">
      <label>Name <input type="text" name="name"></label>
      <label>Email <input type="email" name="email"></label>
      <label>Message <textarea name="message"></textarea></label>
      <button type="submit">Send</button>
    </form>
  <?php endif; ?>
</body>
</html>
