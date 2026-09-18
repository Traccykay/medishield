<?php

declare(strict_types=1);

namespace MediShield\Visit;

/** Maps persisted visit states to presentation-only journey stages. */
final class VisitProgress
{
    /** @return list<array{key:string,label:string,state:string}> */
    public static function stages(string $status): array
    {
        $steps = [
            'reception' => 'Reception',
            'payment' => 'Payment',
            'triage' => 'Triage',
            'doctor' => 'Doctor',
            'lab' => 'Laboratory',
            'pharmacy' => 'Pharmacy',
            'completed' => 'Complete',
        ];
        $current = match ($status) {
            'triage', 'with_nurse' => 'triage',
            'with_doctor' => 'doctor',
            'lab' => 'lab',
            'pharmacy' => 'pharmacy',
            'completed' => 'completed',
            default => 'reception',
        };
        $currentIndex = array_search($current, array_keys($steps), true);

        $result = [];
        foreach ($steps as $key => $label) {
            $index = array_search($key, array_keys($steps), true);
            $result[] = [
                'key' => $key,
                'label' => $label,
                'state' => $index < $currentIndex ? 'complete' : ($key === $current ? 'current' : 'upcoming'),
            ];
        }
        return $result;
    }
}
