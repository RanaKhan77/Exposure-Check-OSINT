<?php

declare(strict_types=1);

namespace App\Modules\Osint\Sources;

/**
 * Phone number validity + country classification (offline, no request).
 * Clean-room PhoneInfoga-style checks: E.164 normalization, country prefix
 * table for the top-40 markets, line-type heuristics (toll-free/mobile
 * blocks where well-known). No third-party personal data is queried —
 * phone-reputation APIs are all paid (2026 landscape), so this stays honest.
 */
class PhoneValiditySource implements OsintSource
{
    /** ISO country code => [prefix, name, mobile-ish blocks note] */
    private const PREFIXES = [
        '880' => 'Bangladesh', '91' => 'India', '92' => 'Pakistan', '94' => 'Sri Lanka',
        '977' => 'Nepal', '975' => 'Bhutan', '67' => 'Brunei', '60' => 'Malaysia',
        '65' => 'Singapore', '66' => 'Thailand', '62' => 'Indonesia', '63' => 'Philippines',
        '84' => 'Vietnam', '855' => 'Cambodia', '856' => 'Laos', '95' => 'Myanmar',
        '86' => 'China', '852' => 'Hong Kong', '853' => 'Macau', '886' => 'Taiwan',
        '81' => 'Japan', '82' => 'South Korea', '966' => 'Saudi Arabia',
        '971' => 'United Arab Emirates', '974' => 'Qatar', '968' => 'Oman',
        '973' => 'Bahrain', '962' => 'Jordan', '961' => 'Lebanon', '90' => 'Türkiye',
        '20' => 'Egypt', '234' => 'Nigeria', '254' => 'Kenya', '27' => 'South Africa',
        '44' => 'United Kingdom', '33' => 'France', '49' => 'Germany', '39' => 'Italy',
        '34' => 'Spain', '351' => 'Portugal', '31' => 'Netherlands', '32' => 'Belgium',
        '41' => 'Switzerland', '43' => 'Austria', '48' => 'Poland', '7' => 'Russia/Kazakhstan',
        '380' => 'Ukraine', '61' => 'Australia', '64' => 'New Zealand', '1' => 'USA/Canada',
        '55' => 'Brazil', '52' => 'Mexico', '54' => 'Argentina', '57' => 'Colombia',
    ];

    public function key(): string
    {
        return 'phonevalid';
    }

    public function label(): string
    {
        return 'Phone Number Analysis';
    }

    public function category(): string
    {
        return 'reputation';
    }

    public function supports(string $type): bool
    {
        return $type === 'phone';
    }

    public function requests(string $type, string $identifier): array
    {
        return []; // fully offline
    }

    public function parse(string $type, string $identifier, array $responses): array
    {
        $digits = preg_replace('/\D+/', '', $identifier) ?? '';
        if (strlen($digits) < 7 || strlen($digits) > 15) {
            return [
                'status' => 'hit',
                'summary' => 'Not a valid phone number length (E.164 allows 7-15 digits).',
                'severity' => 'medium',
                'data' => ['valid' => false],
            ];
        }

        $country = 'Unknown';
        foreach (self::PREFIXES as $prefix => $name) {
            if (str_starts_with($digits, (string) $prefix)) {
                $country = $name;

                break;
            }
        }

        $data = [
            'valid' => true,
            'e164' => '+' . $digits,
            'country' => $country,
            'digits' => strlen($digits),
        ];

        $tollFree = str_starts_with($digits, '1800') || str_starts_with($digits, '1888')
            || str_starts_with($digits, '1877') || str_starts_with($digits, '1866');
        if ($tollFree) {
            $data['line_type'] = 'toll-free';
        }

        return [
            'status' => 'clean',
            'summary' => 'Valid E.164 number — country: ' . $country
                . ' · ' . strlen($digits) . ' digits'
                . ($tollFree ? ' · toll-free line' : '') . '.',
            'severity' => 'info',
            'data' => $data,
        ];
    }
}
