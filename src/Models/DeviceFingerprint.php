<?php

declare( strict_types=1 );

namespace ArtisanPackUI\SecurityAdvancedAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DeviceFingerprint extends Model
{
    /**
     * Indicates if the model should be timestamped.
     */
    public $timestamps = false;

    /**
     * The table associated with the model.
     */
    protected $table = 'device_fingerprints';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'device_id',
        'fingerprint_hash',
        'components',
        'confidence_score',
        'created_at',
    ];

    /**
     * Get the device that owns this fingerprint.
     *
     * @return BelongsTo<UserDevice, DeviceFingerprint>
     */
    public function device(): BelongsTo
    {
        return $this->belongsTo( UserDevice::class, 'device_id' );
    }

    /**
     * Get a specific component value.
     */
    public function getComponent( string $key ): mixed
    {
        return data_get( $this->components, $key );
    }

    /**
     * Calculate similarity score between this fingerprint and another.
     *
     * @return float Score between 0.0 and 1.0
     */
    public function calculateSimilarity( array $otherComponents ): float
    {
        $thisComponents     = $this->components ?? [];
        $matchingComponents = 0;
        $totalComponents    = 0;

        foreach ( $thisComponents as $key => $value ) {
            $totalComponents++;
            if ( isset( $otherComponents[ $key ] ) && $otherComponents[ $key ] === $value ) {
                $matchingComponents++;
            }
        }

        // Check for components in other that aren't in this
        foreach ( $otherComponents as $key => $value ) {
            if ( ! isset( $thisComponents[ $key ] ) ) {
                $totalComponents++;
            }
        }

        return $totalComponents > 0 ? $matchingComponents / $totalComponents : 0.0;
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'components'       => 'array',
            'confidence_score' => 'float',
            'created_at'       => 'datetime',
        ];
    }

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating( function ( $model ): void {
            if ( ! $model->created_at ) {
                $model->created_at = now();
            }
        });
    }
}
