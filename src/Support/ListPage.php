<?php

declare(strict_types=1);

namespace MediShield\Support;

/** Normalizes list paging and slices already-authorized server-side result sets. */
final class ListPage
{
    public const SIZES = [25, 50, 100];

    /** @param list<array<string,mixed>> $rows @return array{rows:array,total:int,page:int,page_count:int,per_page:int} */
    public static function fromRows(array $rows, mixed $page, mixed $perPage): array
    {
        $size = filter_var($perPage, FILTER_VALIDATE_INT);
        $size = in_array($size, self::SIZES, true) ? $size : 25;
        $requested = filter_var($page, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $total = count($rows);
        $pageCount = max(1, (int) ceil($total / $size));
        $current = min($requested === false ? 1 : $requested, $pageCount);

        return [
            'rows' => array_slice($rows, ($current - 1) * $size, $size),
            'total' => $total,
            'page' => $current,
            'page_count' => $pageCount,
            'per_page' => $size,
        ];
    }
}
