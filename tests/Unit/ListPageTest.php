<?php

declare(strict_types=1);

namespace MediShield\Tests\Unit;

use MediShield\Support\ListPage;
use PHPUnit\Framework\TestCase;

final class ListPageTest extends TestCase
{
    public function testSlicesRowsAndReportsBoundaries(): void
    {
        $rows = array_map(static fn (int $id): array => ['id' => $id], range(1, 60));
        $page = ListPage::fromRows($rows, 2, 25);
        self::assertSame(60, $page['total']);
        self::assertSame(3, $page['page_count']);
        self::assertSame(26, $page['rows'][0]['id']);
    }

    public function testRejectsUnsupportedSizesAndClampsPages(): void
    {
        $page = ListPage::fromRows([['id' => 1]], 99, 37);
        self::assertSame(25, $page['per_page']);
        self::assertSame(1, $page['page']);
    }
}
