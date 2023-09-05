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
use Faker\Generator as Faker;


class AuthController extends Controller
{
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
        $loginCitrus = $this->loginCitrus($request->phone, $this->encryptPin($request->pin));
        if ($loginCitrus['status'] != 'SUCCESS') {
            return response()->json(['status' => 'FAIL', 'message' => translate('Invalid credentials supplied'), 'user' => null]);
        }
        $user = User::whereIn('user_type', ['customer'])
            ->where('phone', $loginCitrus['username'])
            ->first();
        if (!$user) {
            $account_id = mt_rand(100000, 999999);
            $account = self::checkAccountNo($account_id);
            $user = new User([
                'name' => $loginCitrus['fullName'] ?? 'Allan Abaho',
                'account_balance' => 0,
                'account_number' => $account['account_no'],
                'phone' => $request->phone,
                'password' => bcrypt($request->pin),
                'verification_code' => rand(100000, 999999),
                'email_verified_at' => Carbon::now()
            ]);

            $user->save();
            $user->createToken('tokens')->plainTextToken;
        } else {
            // update user
            $user->password = bcrypt($request->pin);
            $user->save();
        }
        return $this->loginSuccess($user);
    }

    protected function loginSuccess($user)
    {
        $account = self::queryAccountBalance($user->phone);
        if ($account['status'] !== 'SUCCESS') {
            Log::info($account['message']);
            return response([
                'status' => 'FAIL',
                'message' => $account['message'],
                'user_id' => 0
            ]);
        }
        $user->account_balance = $account['balance'];
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
        ]);
    }

    public function queryAccountBalance($accountNo)
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
                return (['status' => 'FAIL', 'message' => $error_msg]);
            }
            curl_close($ch);
            $result = (json_decode($result, true));
            Log::info('Check account balance', [$result]);
            return ([
                'status' => $result['status'],
                'message' => $result['message'],
                'balance' => str_replace(',', '', $result['balance'])
            ]);
        } catch (Exception $e) {
            Log::info('Wallet Check Exception Error', [$e->getMessage()]);
            return (['status' => 'FAIL', 'message' => $e->getMessage()]);
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

    public function citrusEncryption(Request $request)
    {
        $vendorSecretKey = "CZKGZ9JO2T4OOPQOWET2";
        $encryptionKey = substr(bin2hex($vendorSecretKey), 0, 32);
        $randomString = random_bytes(16);
        $initializationVector = substr(bin2hex($randomString), 0, 16);
        $cipher = "aes-256-cbc";
        $encryptionKey = substr(bin2hex($vendorSecretKey), 0, 32);
        $rawCipherText = openssl_encrypt($request->pin, $cipher, $encryptionKey, OPENSSL_RAW_DATA, $initializationVector);
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
            Log::info('Profile Update Exception Error', [$e->getMessage()]);
            return (['success' => false, 'message' => 'Failed to generate Pivotpay wallet Id, please contact support']);
        }
    }

    public function changePin(Request $request)
    {
        try {
            Log::info('Change PIN Request', [$request]);
            $username = $request->get('username');
            $old_pin = $request->get('old_pin');
            $pin = $request->get('pin');
            if (isset($username)) {
                $url = env('SHABELLE_GATEWAY') . '/changeUserPin';
                $post_data = [
                    'username' => $username,
                    'oldPin' => $this->encryptPin($old_pin),
                    'newPin' => $this->encryptPin($pin),
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                Log::info('Change PIN response', [$result]);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Change PIN Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Change PIN Response', [$result]);

                if ($result['status'] == 'SUCCESS') {
                    $user = User::where('phone', $username)->first();
                    $user->password = bcrypt($pin);
                    $user->save();
                }
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Change PIN Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function resetPin(Request $request)
    {
        try {
            Log::info('Reset PIN Request', [$request]);
            $username = $request->get('username');
            $pin = $request->get('pin');
            if (isset($username)) {
                $url = env('SHABELLE_GATEWAY') . '/resetPin';
                $post_data = [
                    'username' => $username,
                    'old_pin' => '',
                    'pin' => $this->encryptPin($pin),
                    'macAddress' => ''
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                Log::info('Reset PIN response', [$result]);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Reset PIN Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Reset PIN Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Reset PIN Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }


    public function loginCitrus($username, $encryptedPin)
    {
        try {
            // Log::info('Login Citrus Request', [$username, $encryptedPin]);
            if (isset($username)) {
                $url = env('SHABELLE_GATEWAY') . '/login';
                $post_data = [
                    'username' => $username,
                    'pin' => $encryptedPin,
                ];
                Log::info('Login Citrus Request', [$post_data]);

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                Log::info('Login Citrus response', [$result]);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Login Citrus Curl Error.', [$error_msg]);
                    return (['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Login Citrus Response', [$result]);
                return ([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'username' => $result['username'],
                    'marketPlaceAccount' => $result['marketPlaceAccount']
                ]);
            } else {
                return (['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Login Citrus Exception Error', [$e->getMessage()]);
            return (['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }
    public function register(Request $request)
    {
        try {
            Log::info('Register Request', [$request->all()]);
            $name = $request->name;
            $phone = $request->phone;
            $pin = $request->pin;
            if (isset($name) && isset($phone) && isset($pin)) {
                $url = env('SHABELLE_GATEWAY') . '/newUserRegistration';
                $account_id = mt_rand(100000, 999999);
                $account = self::checkAccountNo($account_id);
                $post_data = [
                    'fullName' => $name,
                    'phone' => $phone,
                    'pin' => $this->encryptPin($pin),
                    'email' => 'support@hcash.com',
                    'appVersion' => '4.0.0+46',
                    'checkoutMode' => CHECK_OUT_MODE,
                    'osType' => 'ANDROID',
                    'creation_date' => date('Y-m-d'),
                    'gender' => 'Male',
                    'rimNumber' => '',
                    'marketPlaceAccount' => $account['account_no']
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                Log::info('Register response', [$result]);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Register Curl Error.', [$error_msg]);
                    return (['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                if ($result['status'] == 'SUCCESS') {
                    $user = new User([
                        'name' => $name,
                        'account_balance' => 0,
                        'account_number' => $account['account_no'],
                        'phone' => $phone,
                        'password' => bcrypt($pin),
                        'verification_code' => rand(100000, 999999),
                        'email_verified_at' => Carbon::now()
                    ]);

                    $user->save();
                    $user->createToken('tokens')->plainTextToken;
                }
                return ([
                    'status' => $result['status'],
                    'message' => $result['message'],
                ]);
            } else {
                return (['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Regsiter Citrus Exception Error', [$e->getMessage()]);
            return (['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }
}
