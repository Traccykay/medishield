<?php

declare(strict_types=1);

namespace MediShield\Clinical;

/** Fixed demo catalogue. Prices are resolved server-side and never accepted from forms. */
final class ClinicalCatalog
{
    public const LAB_TESTS = [
        'Complete blood count (CBC)' => 1200,
        'Blood glucose' => 400,
        'Blood smear' => 900,
        'Urinalysis' => 500,
        'Malaria rapid test' => 800,
        'HIV test' => 600,
        'Liver function test' => 1800,
        'Kidney function test' => 1600,
        'Lipid profile' => 1500,
        'Pregnancy test' => 350,
    ];

    public const MEDICATIONS = [
        'Paracetamol 500 mg' => 150,
        'Amoxicillin 500 mg' => 600,
        'Artemether' => 850,
        'Ibuprofen 400 mg' => 250,
        'Metformin 500 mg' => 400,
        'Amlodipine 5 mg' => 300,
        'Omeprazole 20 mg' => 450,
        'Cetirizine 10 mg' => 220,
        'Oral rehydration salts' => 100,
        'Salbutamol inhaler' => 1200,
    ];

    public static function priceForTest(string $test): ?int
    {
        return self::LAB_TESTS[$test] ?? null;
    }

    public static function priceForMedication(string $medication): ?int
    {
        return self::MEDICATIONS[$medication] ?? null;
    }
}
