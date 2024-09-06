<?php

namespace App\Http\Controllers;

use Closure;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

class HackingChallenge extends Controller
{
    public function index()
    {
        $baseUrl = 'https://challenge-bootcamp-evertec.up.railway.app';
        $key = "base64:45n+LJrFVW9CqCLu6DvWEOKCrJxtJxLj/Q8AUWcGBds=";
        $encrypter = new Encrypter(base64_decode(substr($key, 7)), 'AES-256-CBC');

        $token = Cache::remember('challenge_token', 3600, function () use ($baseUrl) {
            $response = $this->authenticate($baseUrl);
            return $response['data']['token'];
        });

        $question = $this->sendHttpRequest("{$baseUrl}/api/question", [], $token);

        $data = $this->getStepData($encrypter, $question);
        $answerPassword = $this->encryptAnswer($encrypter, 'password_hash');

        $setPassword = $this->sendHttpRequest("{$baseUrl}/api/set-password", ["answer" => $answerPassword], $token);
        $data = $this->getStepData($encrypter, $setPassword);
        $formattedCsv = $this->processCsv($data['data']['file_url']);
        $invalidRecords = $this->applyRulesToData($formattedCsv);
        $answer = $this->encryptAnswer($encrypter, implode('-', array_keys($invalidRecords)));
        $fileAnswer = $this->sendHttpRequest("{$baseUrl}/api/file-error-answer", ["answer" => $answer], $token);

        $data = $this->getStepData($encrypter, $fileAnswer);

        return "<h1>Challenge Completed!</h1> <p> {$data['data']['message']} </p>";
    }

    private function authenticate($baseUrl)
    {
        $login = "2aTCUtRwXVxh2HJs06WQJKuUmFcCAaLJ";
        $secretKey = "xHBEFFkZ6lfbaITO";
        $seed = (string) date('c');
        $nonce = (string) rand();

        $tranKey = base64_encode(hash('sha256', $login . $nonce . $seed . $secretKey, true));

        $body = [
            "auth" => [
                "login" => $login,
                "tranKey" => $tranKey,
                "nonce" => $nonce,
                "seed" => $seed,
            ],
        ];

        return $this->sendHttpRequest("{$baseUrl}/api/login", $body, null);
    }

    private function sendHttpRequest($url, $data, $token)
    {
        try {
            if ($token) {
                $response = Http::withToken($token)->post($url, $data);
            } else {
                $response = Http::post($url, $data);
            }

            if ($response->failed()) {
                Log::error("Failed to send request." . $response->body());
                throw new \Exception("Failed to send request.");
            }

            return $response->json();
        } catch (\Throwable $th) {
            Log::error("Failed to send request.." . $th);
            throw new \Exception("Failed to send request.");
        }
    }

    private function getStepData($encrypter, $encryptedQuestion)
    {
        return json_decode($encrypter->decrypt($encryptedQuestion), JSON_PRETTY_PRINT);
    }

    private function encryptAnswer($encrypter, $answer)
    {
        return $encrypter->encrypt($answer);
    }

    private function processCsv($url)
    {

        $data = Cache::remember('csv_data_challenge', 14400, function () use ($url) {
            $response = Http::get($url);

            if ($response->failed()) {
                throw new \Exception("Failed to fetch CSV file from URL.");
            }

            return $response->body();
        });

        $lines = explode("\n", $data);
        $header = str_getcsv(array_shift($lines));
        $records = [];
        $currentRecord = '';

        foreach ($lines as $line) {
            $currentRecord .= $line;
            $quoteCount = substr_count($currentRecord, '"');

            if ($quoteCount % 2 == 0) {
                $records[] = trim($currentRecord);
                $currentRecord = '';
            }
        }

        $formattedData = [];

        foreach ($records as $index => $line) {
            if (empty($line)) {
                continue;
            }

            $formattedData[] = array_combine($header, str_getcsv($line));
        }

        return $formattedData;
    }

    private function applyRulesToData($data)
    {
        $errors = [];
        $rules = [
            'document_type' => 'required|in:CC,CE,NIT,RUT,PPN',
            'email' => 'required|email',
            'account_number' => 'required|digits:10',
        ];

        $documentNumberRules = [
            'CC' => 'regex:/^[1-9][0-9]{4,9}$/',
            'CE' => 'regex:/^([a-zA-Z]{1,5})?[1-9][0-9]{3,7}$/',
            'NIT' => 'regex:/^[1-9][0-9]{6,10}(\-[0-9])?$/',
            'RUT' => 'regex:/^[1-9][0-9]{4,9}(\-[0-9])?$/',
            'PPN' => 'regex:/^[a-zA-Z0-9]{4,12}$/',
        ];

        foreach ($data as $index => $line) {
            $lineRules = $rules;

            if (in_array($line['document_type'], ['CC', 'CE', 'NIT', 'RUT', 'PPN'])) {
                $lineRules['document_number'] = $documentNumberRules[$line['document_type']];
            }

            $validator = Validator::make($line, $lineRules);

            if ($validator->fails()) {
                $errors[$line['id'] + 1] = $validator->errors()->all();
            }
        }

        return $errors;
    }
}
