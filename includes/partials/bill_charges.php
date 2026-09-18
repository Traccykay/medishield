<div class="ms-invoice-lines" aria-label="Invoice charges">
    <?php foreach ($bill['charges'] as $charge) { ?>
        <div class="ms-invoice-line">
            <div class="ms-invoice-line-label"><?= e((string) $charge['description_snapshot']) ?></div>
            <div class="ms-invoice-line-value">KES <?= e(number_format((int) $charge['unit_price_snapshot'])) ?> each</div>
            <div class="ms-invoice-line-value">Qty <?= e((string) $charge['quantity']) ?></div>
            <div class="ms-invoice-line-value"><strong>KES <?= e(number_format((int) $charge['line_total'])) ?></strong></div>
        </div>
    <?php } ?>
</div>
<div class="ms-invoice-total"><span>Total</span><span>KES <?= e(number_format((int) $bill['total_amount'])) ?></span></div>
