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
        Schema::create('webauthn_credentials', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('name', 255);
            $table->text('credential_id');
            $table->string('credential_id_hash', 64)->unique();
            $table->text('public_key');
            $table->string('attestation_type', 50);
            $table->json('transports')->nullable();
            $table->binary('aaguid')->nullable();
            $table->unsignedInteger('sign_count')->default(0);
            $table->boolean('user_verified')->default(false);
            $table->boolean('backup_eligible')->default(false);
            $table->boolean('backup_state')->default(false);
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index('user_id', 'idx_user_credentials');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('webauthn_credentials');
    }
};
