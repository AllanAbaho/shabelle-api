<?php

/** @noinspection PhpUndefinedClassInspection */

namespace App\Http\Controllers\Api\V2;

use App\Http\Controllers\OTPVerificationController;
use App\Models\BusinessSetting;
use App\Models\Customer;
use Illuminate\Http\Request;
use Carbon\Carbon;
use App\Models\User;
use App\Notifications\AppEmailVerificationNotification;
use Hash;
use Socialite;
use Exception;
use Illuminate\Support\Facades\Log;




class AuthController extends Controller
{
    public function registerUser($data)
    {
        try {
            $account_id = '';
            $pic_name = 'imgidfront' . $data['user_name'] . '.png';
            $pic_name_back = 'imgidback' . $data['user_name'] . '.png';
            $pic_name_profile = $data['user_name'] . '.png';
            $folder = public_path() . '/images/';
            $dbImgPathFront = 'images/' . $pic_name;
            $dbImgPathBack = 'images/' . $pic_name_back;
            $dbImgPathProfile = 'images/' . $pic_name_profile;
            file_put_contents($folder . $pic_name, base64_decode($data['profile']));
            file_put_contents($folder . $pic_name_back, base64_decode($data['profile_back']));
            file_put_contents($folder . $pic_name_profile, base64_decode($data['profile_img']));

            $DOE = date('Y-m-d', time());
            $pin = self::encryptPin($data['pin']);

            $account_id = mt_rand(1000000, 9999999);
            $walletDetails = self::checkAccountNo($account_id);
            if ($walletDetails['success']) {
                $account_id = $walletDetails['account_no'];
                if (empty($referral_code)) {
                    $referral_code = "TUMIA RETAIL APP";
                }
                $url = BRIDGE_API . SIGN_UP;
                $post_data = [
                    'username' => $account_id,
                    'username2' => $data['user_name'],
                    'fname' => $data['first_name'],
                    'lname'   => $data['last_name'],
                    'appVersion' => $data['app_version'],
                    'phone'   => $data['phone_number'],
                    'creation_date' => $DOE,
                    'verified' => $data['verified'],
                    'osType' => $data['osType'],
                    'checkoutMode' => CHECK_OUT_MODE,
                    'country'   => $data['country'],
                    'device_id' => $data['deviceId'],
                    'currency_code' => $data['currency'],
                    'profile_pic_url' => env('APP_URL') . '/public/' . $dbImgPathProfile,
                    'id_back_url' =>  env('APP_URL') . '/public/' .  $dbImgPathBack,
                    'id_front_url' =>  env('APP_URL') . '/public/' .  $dbImgPathFront,
                    'pin' => $pin,
                    'email' => $data['email'],
                    'enrolled_by' => $referral_code,
                    'nin'   => $data['id_number']
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(BASIC_AUTH_USERNAME . ':' . BASIC_AUTH_PASSWORD)));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    return (['success' => false, 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                if ($result["status"] === "SUCCESS") {
                    return (['success' => true, 'accountNumber' => $account_id, 'image' => $dbImgPathProfile, 'message' => 'User information has been uploaded Successfully']);
                } else {
                    return (['success' => false, 'message' => $result['message']]);
                }
            } else {
                return (['success' => false, 'message' => $walletDetails['message']]);
            }
        } catch (Exception $e) {
            Log::info('Registration Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => $e->getMessage()]);
        }
    }


    public function signup(Request $request)
    {
        $first_name = $request->get('first_name');
        $last_name = $request->get('second_name');
        $user_name = $request->get('user_name');
        $user_name = strtolower($user_name);
        $phone_number = $request->get('phone_number');
        $app_version = $request->get('appVersion');
        $osType = $request->get('osType');
        $country = $request->get('country');
        $verified = $request->get('verified');
        $currency = $request->get('currency');
        $email = $request->get('email');
        $country_code = $request->get('country_code');
        $id_number = $request->get('id_number');
        $pin = $request->get('pin');
        $deviceId = $request->get('device_id');
        $id_type = $request->get('id_type');
        $referral_code = $request->get('referral_code');

        $profile = $request->get('id_img');
        $profile_back = $request->get('id_img_back');
        $profile_img = $request->get('profile_img');

        if (
            !isset($first_name) || !isset($last_name) || !isset($user_name) || !isset($phone_number) || !isset($app_version) || !isset($country)
            || !isset($currency) || !isset($email) || !isset($country_code) || !isset($id_number) || !isset($deviceId) || !isset($verified)
            || !isset($pin) || !isset($id_type) || !isset($profile) || !isset($profile_back) || !isset($profile_img) || !isset($email)
        ) {
            return response([
                'success' => false,
                'message' => translate('Some parameters missing'),
                'user_id' => 0
            ]);
        }
        $data = [
            'first_name' => $first_name,
            'last_name' => $last_name,
            'user_name' => $user_name,
            'phone_number' => $phone_number,
            'app_version' => $app_version,
            'osType' => $osType,
            'country' => $country,
            'verified' => $verified,
            'currency' => $currency,
            'email' => $email,
            'country_code' => $country_code,
            'id_number' => $id_number,
            'pin' => $pin,
            'deviceId' => $deviceId,
            'id_type' => $id_type,
            'referral_code' => $referral_code,
            'profile' => $profile,
            'profile_back' => $profile_back,
            'profile_img' => $profile_img,
        ];
        if (User::where('phone', $phone_number)->orWhere('email', $email)->first() != null) {
            return response([
                'result' => false,
                'message' => 'User already exists in hustler database',
                'user_id' => 0
            ]);
        }

        $registration = self::registerUser($data);
        if (!$registration['success']) {
            Log::info($registration['message']);
            return response([
                'result' => false,
                'message' => $registration['message'],
                'user_id' => 0
            ]);
        }
        $user = new User([
            'name' => $first_name . ' ' . $last_name,
            'account_number' => $registration['accountNumber'],
            'account_balance' => 0,
            'user_name' => $user_name,
            'phone' => $phone_number,
            'email' => $email,
            'country' => $country,
            'postal_code' => $country_code,
            'password' => bcrypt($pin),
            'verification_code' => rand(100000, 999999)
        ]);

        $user->email_verified_at = null;
        if ($user->email != null) {
            if (BusinessSetting::where('type', 'email_verification')->first()->value != 1) {
                $user->email_verified_at = date('Y-m-d H:m:s');
            }
        }

        // if ($user->email_verified_at == null) {
        //     if ($request->register_by == 'email') {
        //         try {
        //             $user->notify(new AppEmailVerificationNotification());
        //         } catch (\Exception $e) {
        //         }
        //     } else {
        //         $otpController = new OTPVerificationController();
        //         $otpController->send_code($user);
        //     }
        // }

        $user->save();

        //create token
        $user->createToken('tokens')->plainTextToken;

        return response([
            'result' => true,
            'message' => translate('Registration Successful. Please verify and log in to your account.'),
            'user_id' => $user->id,
            'verification_code' => strval($user->verification_code)
        ]);
    }

    public function resendCode(Request $request)
    {
        $user = User::where('id', $request->user_id)->first();
        $user->verification_code = rand(100000, 999999);

        if ($request->verify_by == 'email') {
            $user->notify(new AppEmailVerificationNotification());
        } else {
            $otpController = new OTPVerificationController();
            $otpController->send_code($user);
        }

        $user->save();

        return response()->json([
            'result' => true,
            'message' => translate('Verification code is sent again'),
        ], 200);
    }

    public function checkUserNameExists(Request $request)
    {
        try {
            $username = $request->get('username');
            if (isset($username)) {
                $user = User::where('user_name', '=', $username)->first();
                if ($user != null) {
                    return response([
                        'success' => false,
                        'email' => $user->email,
                        'phone_number' => $user->phone,
                        'message' => 'Username ' . $username . ' already exists.'
                    ]);
                } else {
                    return response(['success' => true, 'message' => 'Username check completed successfully.']);
                }
            } else {
                return response(['success' => false, 'message' => 'Username parameter was not passed in the payload.']);
            }
        } catch (Exception $e) {
            Log::info('Username Check Exception Error', [$e->getMessage()]);
            return response(['success' => false, 'message' => 'Failure to check phonenumber at Pivotpay, connection error please try again.']);
        }
    }



    public function checkPhoneNumberExists(Request $request)
    {
        try {
            $phoneNumber = $request->get('phone');
            if (isset($phoneNumber)) {
                $users = User::where('phone', '=', $phoneNumber)->first();
                if ($users != null) {
                    return response(['success' => false, 'message' => 'Phonenumber ' . $phoneNumber . ' already exists.']);
                } else {
                    return response(['success' => true, 'message' => 'Phonenumber check completed successfully.']);
                }
            } else {
                return response(['success' => false, 'message' => 'User phone number parameter was not passed in the payload.']);
            }
        } catch (Exception $e) {
            Log::info('Phone Number Check Exception Error', [$e->getMessage()]);
            return response(['success' => false, 'message' => 'Failure to check phonenumber at Pivotpay, connection error please try again.']);
        }
    }


    public function confirmCode(Request $request)
    {
        $user = User::where('id', $request->user_id)->first();

        if ($user->verification_code == $request->verification_code) {
            $user->email_verified_at = date('Y-m-d H:i:s');
            $user->verification_code = null;
            $user->save();
            return response()->json([
                'result' => true,
                'message' => translate('Your account is now verified.Please login'),
            ], 200);
        } else {
            return response()->json([
                'result' => false,
                'message' => translate('Code does not match, you can request for resending the code'),
            ], 200);
        }
    }

    public function login(Request $request)
    {
        /*$request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);*/

        $delivery_boy_condition = $request->has('user_type') && $request->user_type == 'delivery_boy';
        $seller_condition = $request->has('user_type') && $request->user_type == 'seller';

        if ($delivery_boy_condition) {
            $user = User::whereIn('user_type', ['delivery_boy'])
                ->where('phone', $request->phone)
                ->first();
        } elseif ($seller_condition) {
            $user = User::whereIn('user_type', ['seller'])
                ->where('phone', $request->phone)
                ->first();
        } else {
            $user = User::whereIn('user_type', ['customer'])
                ->where('phone', $request->phone)
                ->first();
        }
        $identity_matrix = "6f56de4a-0426-45e0-bf02-d0bb7caabeb3";


        // if (!$delivery_boy_condition) {
        if (!$delivery_boy_condition && !$seller_condition) {
            if (\App\Utility\PayhereUtility::create_wallet_reference($identity_matrix) == false) {
                return response()->json(['result' => false, 'message' => 'Identity matrix error', 'user' => null]);
            }
        }


        if ($user != null) {
            if (Hash::check($request->pin, $user->password)) {

                if ($user->email_verified_at == null) {
                    return response()->json(['result' => false, 'message' => translate('Please verify your account'), 'user' => null]);
                }
                return $this->loginSuccess($user);
            } else {
                return response()->json(['result' => false, 'message' => translate('Invalid credentials supplied'), 'user' => null]);
            }
        } else {
            return response()->json(['result' => false, 'message' => translate('Invalid credentials supplied'), 'user' => null]);
        }
    }

    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    public function logout(Request $request)
    {

        $user = request()->user();
        $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();

        return response()->json([
            'result' => true,
            'message' => translate('Successfully logged out')
        ]);
    }

    public function socialLogin(Request $request)
    {
        if (!$request->provider) {
            return response()->json([
                'result' => false,
                'message' => translate('User not found'),
                'user' => null
            ]);
        }

        //
        switch ($request->social_provider) {
            case 'facebook':
                $social_user = Socialite::driver('facebook')->fields([
                    'name',
                    'first_name',
                    'last_name',
                    'email'
                ]);
                break;
            case 'google':
                $social_user = Socialite::driver('google')
                    ->scopes(['profile', 'email']);
                break;
            default:
                $social_user = null;
        }
        if ($social_user == null) {
            return response()->json(['result' => false, 'message' => translate('No social provider matches'), 'user' => null]);
        }

        $social_user_details = $social_user->userFromToken($request->access_token);

        if ($social_user_details == null) {
            return response()->json(['result' => false, 'message' => translate('No social account matches'), 'user' => null]);
        }

        //

        $existingUserByProviderId = User::where('provider_id', $request->provider)->first();

        if ($existingUserByProviderId) {
            return $this->loginSuccess($existingUserByProviderId);
        } else {

            $existingUserByMail = User::where('email', $request->email)->first();
            if ($existingUserByMail) {

                return response()->json(['result' => false, 'message' => translate('You can not login with this provider'), 'user' => null]);
            } else {

                $user = new User([
                    'name' => $request->name,
                    'email' => $request->email,
                    'provider_id' => $request->provider,
                    'email_verified_at' => Carbon::now()
                ]);
                $user->save();
            }
        }
        return $this->loginSuccess($user);
    }

    protected function loginSuccess($user)
    {
        $account = self::queryAccount($user->phone);
        if (!$account['success']) {
            Log::info($account['message']);
            return response([
                'result' => false,
                'message' => $account['message'],
                'user_id' => 0
            ]);
        }

        $user->account_balance = $account['balance'];
        // $user->sacco_name = $account['sacco_name'];
        // $user->sacco_balance = $account['sacco_balance'];
        $user->save();

        $token = $user->createToken('API Token')->plainTextToken;
        return response()->json([
            'status' => 'SUCCESS',
            'message' => translate('Successfully logged in'),
            'access_token' => $token,
            'phone' => $user->phone,
            'balance' => $user->account_balance,
            'name' => $user->name,
            'avatar' => uploaded_asset($user->avatar_original),
            'user_id' => $user->id,

            // 'token_type' => 'Bearer',
            // 'expires_at' => null,
            // 'user' => [
            //     'id' => $user->id,
            //     'type' => $user->user_type,
            //     'name' => $user->name,
            //     // 'email' => $user->email,
            //     'avatar' => $user->avatar,
            //     'avatar_original' => uploaded_asset($user->avatar_original),
            //     'phone' => $user->phone,
            //     // 'account_number' => $user->account_number,
            //     'account_balance' => $user->account_balance,
            //     // 'sacco_balance' => $account['sacco_balance'],
            //     // 'sacco_name' => $account['sacco_name']
            // ]
        ]);
    }

    public function queryCitrusBalance($accountNo)
    {
        try {
            $url = BRIDGE_API . CITRUS_QUERY_BALANCE;
            $post_data = [
                'username' => $accountNo,
            ];
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
            curl_setopt($ch, CURLOPT_TIMEOUT, 0);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(BASIC_AUTH_USERNAME . ':' . BASIC_AUTH_PASSWORD)));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $result = curl_exec($ch);
            if (curl_errno($ch)) {
                $error_msg = curl_error($ch);
                Log::info('Query Wallet Curl Error', [$error_msg]);
                return (['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
            }
            curl_close($ch);
            $result = (json_decode($result, true));
            if ($result["status"] === "SUCCESS") {
                return (['success' => true, 'balance' => str_replace(',', '', $result['balance'])]);
            } else {
                return (['success' => false, 'message' => $result['message']]);
            }
        } catch (Exception $e) {
            Log::info('Wallet Check Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => 'Failure to check wallet account at Pivotpay, connection error please try again.']);
        }
    }

    public function queryAccount($accountNo)
    {
        try {
            $url = BRIDGE_API . CITRUS_QUERY_ACCOUNT;
            $post_data = [
                'username' => $accountNo,
            ];
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
            curl_setopt($ch, CURLOPT_TIMEOUT, 0);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(BASIC_AUTH_USERNAME . ':' . BASIC_AUTH_PASSWORD)));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $result = curl_exec($ch);
            if (curl_errno($ch)) {
                $error_msg = curl_error($ch);
                Log::info('Query Wallet Curl Error', [$error_msg]);
                return (['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
            }
            curl_close($ch);
            $result = (json_decode($result, true));
            if ($result["status"] === "SUCCESS") {
                return ([
                    'success' => true,
                    'balance' => str_replace(',', '', $result['balance'])
                ]);
            } else {
                return (['success' => false, 'message' => $result['message']]);
            }
        } catch (Exception $e) {
            Log::info('Wallet Check Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => $e->getMessage()]);
        }
    }

    public function queryAccountDetails(Request $request)
    {
        $accountNo = $request->username;
        try {
            $url = BRIDGE_API . CITRUS_QUERY_ACCOUNT;
            $post_data = [
                'username' => $accountNo,
            ];
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
            curl_setopt($ch, CURLOPT_TIMEOUT, 0);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(BASIC_AUTH_USERNAME . ':' . BASIC_AUTH_PASSWORD)));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $result = curl_exec($ch);
            if (curl_errno($ch)) {
                $error_msg = curl_error($ch);
                Log::info('Query Wallet Curl Error', [$error_msg]);
                return (['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
            }
            curl_close($ch);
            $result = (json_decode($result, true));
            if ($result["status"] === "SUCCESS") {
                return ([
                    'success' => true,
                    'account_balance' => str_replace(',', '', $result['display_amount']),
                    'sacco_balance' => str_replace(',', '', $result['sacco_balance']),
                    'sacco_name' => $result['sacco_name']
                ]);
            } else {
                return (['success' => false, 'message' => $result['message']]);
            }
        } catch (Exception $e) {
            Log::info('Wallet Check Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => 'Failure to check wallet account at Pivotpay, connection error please try again.']);
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
                $account_id = mt_rand(100000000, 999999999);
                self::checkAccountNo($account_id);
            } else {
                return (['success' => true, 'account_no' => $account_id]);
            }
        } catch (Exception $e) {
            Log::info('Profile Update Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => 'Failed to generate Pivotpay wallet Id, please contact support']);
        }
    }
}
