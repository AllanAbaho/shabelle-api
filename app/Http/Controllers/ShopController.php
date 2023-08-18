<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Shop;
use App\Models\User;
use App\Models\BusinessSetting;
use Auth;
use Hash;
use App\Notifications\EmailVerificationNotification;
use Exception;

class ShopController extends Controller
{

    public function __construct()
    {
        $this->middleware('user', ['only' => ['index']]);
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $shop = Auth::user()->shop;
        return view('seller.shop', compact('shop'));
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        if (Auth::check()) {
            if ((Auth::user()->user_type == 'admin' || Auth::user()->user_type == 'customer')) {
                flash(translate('Admin or Customer can not be a seller'))->error();
                return back();
            }
            if (Auth::user()->user_type == 'seller') {
                flash(translate('This user already a seller'))->error();
                return back();
            }
        } else {
            return view('frontend.seller_form');
        }
    }

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
                flash(translate('Email already exists!'))->error();
                return back();
            }
            if ($request->password == $request->password_confirmation) {
                $user = new User;
                $user->name = $request->name;
                $user->email = $request->email;
                $user->phone = $request->phone;
                $user->user_type = "seller";
                $user->password = Hash::make($request->password);
                $user->save();
            } else {
                flash(translate('Sorry! Password did not match.'))->error();
                return back();
            }
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

            if ($shop->save()) {
                // auth()->login($user, false);
                if (BusinessSetting::where('type', 'email_verification')->first()->value != 1) {
                    $user->email_verified_at = date('Y-m-d H:m:s');
                    $user->save();
                } else {
                    $user->notify(new EmailVerificationNotification());
                }
                $pin = $request->password;
                $result = self::createCitrusSellerAccount($user, $shop, $pin);
                if ($result['success']) {


                    flash(translate('Your Shop has been created successfully!'))->success();
                    return redirect()->route('user.login');
                } else {
                    $shop->delete();
                    $user->delete();
                    flash(translate($result['message']))->error();
                    return back();
                }
            }
        }

        flash(translate('Sorry! Something went wrong.'))->error();
        return back();
    }

    public function createCitrusSellerAccount($user, $shop, $pin)
    {
        try {
            $name = $shop->name;
            $email = $user->email;
            $address = $shop->address;
            if (
                isset($name) && isset($email) && isset($pin) && isset($address)
            ) {
                $pin = self::encryptPin($pin);
                $account_id = mt_rand(100000, 999999);
                $walletDetails = self::checkAccountNo($account_id);
                if ($walletDetails['success']) {
                    $account_id = $walletDetails['account_no'];
                    $url = BRIDGE_API . 'registerSeller';
                    $post_data = [
                        'fullName' => $user->name,
                        'email' => $email,
                        'pin' => $pin,
                        'phoneNumber' => $user->phone,
                        'address' => $address,
                        'username' => $account_id,
                        'shopName' => $name
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
                    if ($result['status'] == 'SUCCESS') {
                        $updateUser = User::where('email', $user->email)->first();
                        $updateUser->account_number = $account_id;
                        $updateUser->account_balance = 0;
                        $updateUser->save();
                        return (['success' => true, 'message' => 'Shop added to citrus successfully']);
                    } else {
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
            return (['success' => false, 'message' => 'Failed to generate wallet Id, please contact support']);
        }
    }





    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function edit($id)
    {
        //
    }

    public function destroy($id)
    {
        //
    }
}
