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
        Schema::create('user_devices', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('fingerprint_hash', 64);
            $table->string('name', 255)->nullable();
            $table->enum('type', ['desktop', 'mobile', 'tablet', 'unknown'])->default('unknown');
            $table->string('browser', 100)->nullable();
            $table->string('browser_version', 50)->nullable();
            $table->string('os', 100)->nullable();
            $table->string('os_version', 50)->nullable();
            $table->boolean('is_trusted')->default(false);
            $table->timestamp('trusted_at')->nullable();
            $table->timestamp('trust_expires_at')->nullable();
            $table->string('last_ip_address', 45)->nullable();
            $table->json('last_location')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->unsignedInteger('login_count')->default(0);
            $table->timestamps();

            $table->unique(['user_id', 'fingerprint_hash'], 'unique_user_device');
            $table->index('fingerprint_hash', 'idx_fingerprint');
            $table->index(['user_id', 'is_trusted'], 'idx_trusted');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('user_devices');
    }
};
