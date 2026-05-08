<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('device_fingerprints', function (Blueprint $table) {
            $table->id();
            $table->foreignId('device_id')->constrained('user_devices')->cascadeOnDelete();
            $table->string('fingerprint_hash', 64);
            $table->json('components');
            // Confidence score between 0 and 1 (validated at application level)
            $table->decimal('confidence_score', 3, 2)->default(0);
            $table->timestamp('created_at')->nullable();

            $table->index('fingerprint_hash', 'idx_hash');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('device_fingerprints');
    }
};
