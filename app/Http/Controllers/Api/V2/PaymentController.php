<?php

namespace App\Http\Controllers\Api\V2;

use Illuminate\Http\Request;
use Exception;
use Illuminate\Support\Facades\Log;

class PaymentController extends Controller
{
    public function cashOnDelivery(Request $request)
    {
        $order = new OrderController;
        return $order->store($request);
    }

    public function manualPayment(Request $request)
    {
        $order = new OrderController;
        return $order->store($request);
    }

    public function processUtilityPayment(Request $request)
    {
        try {
            Log::info('Process Utility Payment Request', [$request]);
            $toAccount = $request->get('toAccount');
            $fromAccount = $request->get('fromAccount');
            $transactionAmount = $request->get('transactionAmount');
            $narration = $request->get('narration');
            $serviceName = $request->get('serviceName');
            $senderName = $request->get('senderName');
            $receiverName = $request->get('receiverName');
            $airline = 'Ethiopian Airlines';
            $accountParticulars = $request->get('accountParticulars');
            $bankName = $request->get('bankName');

            if (isset($toAccount) && isset($fromAccount) && isset($transactionAmount) && isset($narration) && isset($serviceName) && isset($senderName) && isset($receiverName)) {
                $transactionId = mt_rand(10000000, 99999999) . $senderName;
                $transactionId = str_replace(' ', '', $transactionId);
                $appVersion = '4.0.0+46';
                $checkoutMode = 'SHABELLEWALLET';
                $walletId = $fromAccount;
                $debitType = 'WALLET';
                $fromCurrency = 'UGX';
                $toCurrency = 'UGX';
                $fromAmount = $transactionAmount;
                $toAmount = $transactionAmount;
                $osType = 'ANDROID';
                $url = env('SHABELLE_GATEWAY') . '/processUtilityPayment';
                $post_data = [
                    'toAccount' => $toAccount,
                    'fromAccount' => $fromAccount,
                    'transactionAmount' => $transactionAmount,
                    'narration' => $narration,
                    'utilityName' => $serviceName,
                    'senderName' => $senderName,
                    'receiverName' => $receiverName,
                    'transactionId' => $transactionId,
                    'appVersion' => $appVersion,
                    'checkoutMode' => $checkoutMode,
                    'debitType' => $debitType,
                    'fromCurrency' => $serviceName == 'BANK_TRANSFERS' ? 'ETB' : $fromCurrency,
                    'toCurrency' => $serviceName == 'BANK_TRANSFERS' ? 'ETB' : $toCurrency,
                    'fromAmount' => $fromAmount,
                    "phoneNumber" => $fromAccount,
                    'toAmount' => $toAmount,
                    'osType' => $osType,
                    'walletId' => $walletId,
                    'location' => 'Ethiopia',
                    "authCode" => $accountParticulars,
                    "tranCharge" => "300",
                    "serviceFee" => "0",
                    "airline" => $airline,
                    'customerCategory' => $bankName
                ];

                Log::info('Post Data', [$post_data]);


                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Process Utility Payment Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Process Utility Payment Response', [$result, $transactionId]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactionId' => $result['transactionid'],
                    'appTransactionId' => $transactionId
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Process Utility Payment Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function authorizePayment(Request $request)
    {
        try {
            Log::info('Authorize Payment Request', [$request]);
            $otp = $request->get('otp');
            $walletId = $request->get('walletId');
            $tranType = $request->get('tranType');
            $tranReference = $request->get('tranReference');

            if (isset($otp) && isset($walletId) && isset($tranType) && isset($tranReference)) {
                $appVersion = '4.0.0+46';
                $checkoutMode = 'SHABELLEWALLET';
                $osType = 'ANDROID';
                $url = env('SHABELLE_GATEWAY') . '/authorizeWalletPayment';
                $post_data = [
                    'otp' => $otp,
                    'walletId' => $walletId,
                    'tranType' => $tranType,
                    'tranReference' => $tranReference,
                    'appVersion' => $appVersion,
                    'checkoutMode' => $checkoutMode,
                    'osType' => $osType,
                ];

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Authorize Payment Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Authorize Payment Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactionId' => $result['transactionid'] ?? '',
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Authorize Payment Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function validateMobileMoney(Request $request)
    {
        try {
            Log::info('Validate Mobile Money Number Request', [$request]);
            $accountNumber = $request->get('accountNumber');
            $transactionAmount = $request->get('transactionAmount');
            if (isset($accountNumber) && isset($transactionAmount)) {
                $url = env('VALIDATION_GATEWAY') . '/validateMobileMoneyAccount';
                $post_data = [
                    'accountNumber' => $accountNumber,
                    'transactionAmount' => $transactionAmount,
                    'accountType' => 'MOBILEMONEY',
                    'vendorCode' => 'SHABELLE_APP',
                    'password' => 'EVJ7O9V6Q6'
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Validate Mobile Money Number Curl Error', [$error_msg]);
                    return response(['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Validate Mobile Money Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'accountNumber' => $result['accountNumber'],
                    'accountName' => $result['accountName'],
                    'tranCharge' => $result['tranCharge'],
                    'transactionAmount' => $result['transactionAmount']
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Mobile Money Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function validateBankAccount(Request $request)
    {
        try {
            Log::info('Validate Bank Account Number Request', [$request]);
            $accountNumber = $request->get('accountNumber');
            $transactionAmount = $request->get('transactionAmount');
            $bank = $request->get('bank');
            if (isset($accountNumber) && isset($transactionAmount) && isset($bank)) {
                $url = env('VALIDATION_GATEWAY') . '/validateBankAccount';
                $post_data = [
                    'accountNumber' => $accountNumber,
                    'transactionAmount' => $transactionAmount,
                    'bank' => $bank,
                    'accountType' => 'BANK',
                    'accountCategory' => 'INTERNAL',
                    'vendorCode' => 'SHABELLE_APP',
                    'password' => 'EVJ7O9V6Q6',
                    'countryCode' => 'ETH'
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Validate Bank Account Number Curl Error', [$error_msg]);
                    return response(['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Validate Bank Account Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'accountNumber' => $result['accountNumber'],
                    'accountName' => $result['accountName'],
                    'tranCharge' => $result['tranCharge'],
                    'transactionAmount' => $result['transactionAmount'],
                    'accountParticulars' => $result['accountParticulars']
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Bank Account Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function validatePayBillAccount(Request $request)
    {
        try {
            Log::info('Validate Pay Bill Account Number Request', [$request]);
            $accountNumber = $request->get('accountNumber');
            $transactionAmount = $request->get('transactionAmount');
            $serviceName = $request->get('serviceName');
            if (isset($accountNumber) && isset($transactionAmount) && isset($serviceName)) {
                $url = env('VALIDATION_GATEWAY') . '/validatePayBillAccount';
                $post_data = [
                    "accountNumber" => $accountNumber,
                    "transactionAmount" => $transactionAmount,
                    "accountType" => "PAYBILL",
                    "accountCategory" => "POSTPAID",
                    "serviceName" => $serviceName,
                    "amount" => $transactionAmount,
                    "vendorCode" => "SHABELLE_APP",
                    "password" => "EVJ7O9V6Q6",
                    "countryCode" => "ETH"
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Validate Pay Bill Account Number Curl Error', [$error_msg]);
                    return response(['success' => false, 'message' => 'Failure at Pivot Payments, Please contact support.']);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Validate Pay Bill Account Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'accountNumber' => $result['accountNumber'],
                    'accountName' => $result['accountName'],
                    'tranCharge' => $result['tranCharge'],
                    'transactionAmount' => $result['transactionAmount'] ?? ''
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Pay Bill Account Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }


    public function makePayment(Request $request)
    {
        try {
            Log::info('Make Payment Request', [$request]);
            $toAccount = $request->get('toAccount');
            $fromAccount = $request->get('fromAccount');
            $transactionAmount = $request->get('transactionAmount');
            $narration = $request->get('narration');
            $serviceName = $request->get('serviceName');
            $senderName = $request->get('senderName');
            $receiverName = $request->get('receiverName');

            if (isset($toAccount) && isset($fromAccount) && isset($transactionAmount) && isset($narration) && isset($serviceName) && isset($senderName) && isset($receiverName)) {
                $transactionId = mt_rand(10000000, 99999999) . $senderName;
                $transactionId = str_replace(' ', '', $transactionId);
                $appVersion = '4.0.0+46';
                $checkoutMode = 'SHABELLEWALLET';
                $walletId = $fromAccount;
                $debitType = 'WALLET';
                $fromCurrency = 'UGX';
                $toCurrency = 'UGX';
                $fromAmount = $transactionAmount;
                $toAmount = $transactionAmount;
                $osType = 'ANDROID';
                $url = env('SHABELLE_GATEWAY') . '/processWalletPayment';
                $post_data = [
                    'toAccount' => $toAccount,
                    'fromAccount' => $fromAccount,
                    'transactionAmount' => $transactionAmount,
                    'narration' => $narration,
                    'serviceName' => $serviceName,
                    'senderName' => $senderName,
                    'receiverName' => $receiverName,
                    'transactionId' => $transactionId,
                    'appVersion' => $appVersion,
                    'checkoutMode' => $checkoutMode,
                    'debitType' => $debitType,
                    'fromCurrency' => $fromCurrency,
                    'toCurrency' => $toCurrency,
                    'fromAmount' => $fromAmount,
                    "phoneNumber" => $fromAccount,
                    'toAmount' => $toAmount,
                    'osType' => $osType,
                    'walletId' => $walletId,
                    'location' => 'Ethiopia'
                ];

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Payment Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Payment Response', [$result, $transactionId]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactionId' => $result['transactionid'],
                    'appTransactionId' => $transactionId
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Payment Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function getTransactions(Request $request)
    {
        try {
            Log::info('Get Transactions Request', [$request]);
            $username = $request->get('username');
            $startDate = $request->get('startDate');
            $endDate = $request->get('endDate');

            if (isset($username) && isset($startDate) && isset($endDate)) {
                $url = env('SHABELLE_GATEWAY') . '/getClientTransactionStatement';
                $post_data = [
                    'username' => $username,
                    'startDate' => $startDate,
                    'endDate' => $endDate,
                ];

                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Get Transactions Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Get Transactions Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'transactions' => $result['appTransactions'] ?? [],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Get Transactions Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function checkStatus(Request $request)
    {
        try {
            Log::info('check Status Request', [$request]);
            $transactionId = $request->get('transactionId');

            if (isset($transactionId)) {
                $url = env('SHABELLE_GATEWAY') . '/getTransactionStatus/' . $transactionId;
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('check Status Curl Error', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('check Status Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'] ?? '',
                    'finalStatus' => $result['finalStatus'] ?? '',
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('check Status Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function register(Request $request)
    {
        try {
            Log::info('Register User Request', [$request]);
            $name = $request->get('name');
            $phone = $request->get('phone');
            $pin = $request->get('pin');
            if (isset($phone) && isset($pin)) {
                $pin = self::encryptPin($pin);
                $url = env('SHABELLE_GATEWAY') . '/newUserRegistration';
                $post_data = [
                    'fullName' => $name,
                    'phone' => $phone,
                    'pin' => $pin,
                    "appVersion" => "4.0.0+46",
                    "checkoutMode" => "SHABELLEWALLET",
                    "osType" => "ANDROID",
                    "creation_date" => date('Y-m-d'),
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Register User Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Register User Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Register User Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
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

    public function validateAccount(Request $request)
    {
        try {
            Log::info('Validate Account Request', [$request]);
            $walletId = $request->get('walletId');
            if (isset($walletId)) {
                $url = env('SHABELLE_GATEWAY') . '/queryAccountDetails';
                $post_data = [
                    'username' => $walletId,
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Validate Account Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Validate Account Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'message' => $result['message'],
                    'walletId' => $result['walletId'] ?? '',
                    'name' => $result['name'] ?? '',
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Account Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }

    public function queryWalletBalance(Request $request)
    {
        try {
            Log::info('Query Wallet Balance Request', [$request]);
            $username = $request->get('username');
            if (isset($username)) {
                $url = env('SHABELLE_GATEWAY') . '/queryWalletBalance';
                $post_data = [
                    'username' => $username,
                ];
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_data));
                curl_setopt($ch, CURLOPT_TIMEOUT, 0);
                curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json', 'Authorization: Basic ' . base64_encode(env('SHABELLE_GATEWAY_USERNAME') . ':' . env('SHABELLE_GATEWAY_PASSWORD'))));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                $result = curl_exec($ch);
                if (curl_errno($ch)) {
                    $error_msg = curl_error($ch);
                    Log::info('Query Wallet Balance Curl Error.', [$error_msg]);
                    return response(['status' => 'FAIL', 'message' => $error_msg]);
                }
                curl_close($ch);
                $result = (json_decode($result, true));
                Log::info('Query Wallet Balance Response', [$result]);
                return response([
                    'status' => $result['status'],
                    'balance' => str_replace(',', '', $result['balance'])
                ]);
            } else {
                return response(['status' => 'FAIL', 'message' => 'Invalid request, some parameters were not passed in the payload. Please update your app from google play store.']);
            }
        } catch (Exception $e) {
            Log::info('Validate Account Exception Error', [$e->getMessage()]);
            return response(['status' => 'FAIL', 'message' => $e->getMessage()]);
        }
    }
}
