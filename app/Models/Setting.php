<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property string $key
 * @property mixed $value
 *
 * @method static self updateOrCreate(array $attributes, array $values = [])
 * @method static self firstOrCreate(array $attributes, array $values = [])
 */
class Setting extends Model
{
    protected $table = 'settings';

    protected $fillable = ['key', 'value'];

    protected $casts = ['value' => 'json'];
}
