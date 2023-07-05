<?php

namespace App\Http\Controllers\Api\V2;

use App\Http\Resources\V2\ProductCollection;
use App\Http\Resources\V2\ProductMiniCollection;
use App\Http\Resources\V2\ShopCollection;
use App\Http\Resources\V2\ShopDetailsCollection;
use App\Models\Product;
use App\Models\Shop;
use Illuminate\Http\Request;
use App\Utility\SearchUtility;
use Cache;
use App\Models\User;
use App\Models\BusinessSetting;
use Auth;
use Exception;
use Hash;
use App\Notifications\EmailVerificationNotification;

class ShopController extends Controller
{

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $user = null;
        if (!Auth::check()) {
            if (User::where('email', $request->email)->first() != null) {
                return (['success' => false, 'message' => 'Email already exists!']);
            }
            $user = new User;
            $user->name = $request->name;
            $user->email = $request->email;
            $user->user_type = "seller";
            $user->password = Hash::make($request->password);
            $pin = $request->password;
            $user->save();
        } else {
            $user = Auth::user();
            if ($user->customer != null) {
                $user->customer->delete();
            }
            $user->user_type = "seller";
            $user->save();
        }


        if (Shop::where('user_id', $user->id)->first() == null) {
            $shop = new Shop;
            $shop->user_id = $user->id;
            $shop->name = $request->name;
            $shop->address = $request->address;
            $shop->slug = preg_replace('/\s+/', '-', $request->name);
            $shop->verification_status = 1;
            if ($shop->save()) {
                auth()->login($user, false);
                $user->email_verified_at = date('Y-m-d H:m:s');
                $user->save();
                $result = self::createCitrusSellerAccount($user, $shop, $pin);
                if($result['success']){
                    return (['success' => true, 'message' => 'Your Shop has been created successfully!']);
                }else{
                    $shop->delete();
                    $user->delete();
                    return (['success' => false, 'message' => $result['message']]);
                }
            } else {
                $user->user_type == 'customer';
                $user->save();
            }
        }

        return (['success' => false, 'message' => 'Sorry! Something went wrong.']);
    }

    public function encryptPin($pin)
    {
        $vendorSecretKey = "CZKGZ9JO2T4OOPQOWET2";
        $encryptionKey = substr(bin2hex($vendorSecretKey), 0, 32);
        $randomString = random_bytes(16);
        $initializationVector = substr(bin2hex($randomString), 0, 16);
        $cipher = "aes-256-cbc";
        $encryptionKey = substr(bin2hex($vendorSecretKey), 0, 32);
        $rawCipherText = openssl_encrypt($pin, $cipher, $encryptionKey, OPENSSL_RAW_DATA, $initializationVector);
        $encryption = base64_encode($rawCipherText);
        return $initializationVector . $encryption;
    }

    public function checkAccountNo($account_id)
    {
        try {
            $user = User::where('account_number', '=', $account_id)->first();
            if ($user !=  null) {
                $account_id = mt_rand(100000, 999999);
                self::checkAccountNo($account_id);
            } else {
                return (['success' => true, 'account_no' => $account_id]);
            }
        } catch (Exception $e) {
            // Log::info('Profile Update Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => 'Failed to generate Pivotpay wallet Id, please contact support']);
        }
    }



    public function createCitrusSellerAccount($user, $shop, $pin)
    {
        try {
            $name = $shop->name;
            $email = $user->email;
            $currency_code = 'KES';
            $country = 'KENYA';
            $address = $shop->address;
            if (
                isset($name) && isset($email) && isset($pin) && isset($currency_code) && isset($address) && isset($country)
            ) {
                $pin = self::encryptPin($pin);
                $account_id = mt_rand(100000, 999999);
                $walletDetails = self::checkAccountNo($account_id);
                if ($walletDetails['success']) {
                    $account_id = $walletDetails['account_no'];
                    $url = BRIDGE_API . 'registerSeller';
                    $post_data = [
                        'shopName' => $name,
                        'shopEmail' => $email,
                        'shopPin' => $pin,
                        'currencyCode' => $currency_code,
                        'country' => $country,
                        'shopAddress' => $address,
                        'accountId' => $account_id,
                        "appVersion" => "1.0.0+1",
                        "checkoutMode" => "HUSTLAZWALLET",
                        "osType" => "ANDROID"
                    ];
                    $ch = curl_init($url);
                    curl_setopt($ch, CURLOPT_POST, 1);
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                    curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(BASIC_AUTH_USERNAME . ':' . BASIC_AUTH_PASSWORD)));
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    $result = curl_exec($ch);
                    if (curl_errno($ch)) {
                        return (['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
                    }
                    curl_close($ch);
                    $result = (json_decode($result, true));
                    if($result['status'] == 'SUCCESS'){
                        $updateUser = User::where('email', $user->email)->first();
                        $updateUser->account_number = $account_id;
                        $updateUser->account_balance = 0;
                        $updateUser->save();
                        return (['success' => true, 'message' => 'Shop added to citrus successfully']);
                    }else{
                        return (['success' => false, 'message' => $result['message']]);
                    }
                } else {
                    return (['success' => false, 'message' => $walletDetails['message']]);
                }
            } else {
                return (['success' => false, 'message' => 'Invalid request, some parameters were not passed in the payload.']);
            }
        } catch (Exception $e) {
            return (['success' => false, 'message' => 'Failure to register user at Pivotpay, connection error please try again.']);
        }
    }

    public function index(Request $request)
    {
        $shop_query = Shop::query();

        if ($request->name != null && $request->name != "") {
            $shop_query->where("name", 'like', "%{$request->name}%");
            SearchUtility::store($request->name);
        }

        return new ShopCollection($shop_query->whereIn('user_id', verified_sellers_id())->paginate(10));

        //remove this , this is for testing
        //return new ShopCollection($shop_query->paginate(10));
    }

    public function info($id)
    {
        return new ShopDetailsCollection(Shop::where('id', $id)->first());
    }

    public function shopOfUser($id)
    {
        return new ShopCollection(Shop::where('user_id', $id)->get());
    }

    public function allProducts($id)
    {
        $shop = Shop::findOrFail($id);
        return new ProductCollection(Product::where('user_id', $shop->user_id)->where('published', 1)->latest()->paginate(10));
    }

    public function topSellingProducts($id)
    {
        $shop = Shop::findOrFail($id);

        return Cache::remember("app.top_selling_products-$id", 86400, function () use ($shop) {
            return new ProductMiniCollection(Product::where('user_id', $shop->user_id)->where('published', 1)->orderBy('num_of_sale', 'desc')->limit(10)->get());
        });
    }

    public function featuredProducts($id)
    {
        $shop = Shop::findOrFail($id);

        return Cache::remember("app.featured_products-$id", 86400, function () use ($shop) {
            return new ProductMiniCollection(Product::where(['user_id' => $shop->user_id, 'seller_featured' => 1])->where('published', 1)->latest()->limit(10)->get());
        });
    }

    public function newProducts($id)
    {
        $shop = Shop::findOrFail($id);

        return Cache::remember("app.new_products-$id", 86400, function () use ($shop) {
            return new ProductMiniCollection(Product::where('user_id', $shop->user_id)->where('published', 1)->orderBy('created_at', 'desc')->limit(10)->get());
        });
    }

    public function brands($id)
    {
    }
}
