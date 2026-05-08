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
        Schema::create('sso_identities', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('idp_id', 100);
            $table->string('idp_user_id', 255);
            $table->string('name_id', 255)->nullable();
            $table->json('attributes')->nullable();
            $table->string('session_index', 255)->nullable();
            $table->timestamp('last_authenticated_at')->nullable();
            $table->timestamps();

            $table->unique(['idp_id', 'idp_user_id'], 'unique_idp_user');
            $table->index(['user_id', 'idp_id'], 'idx_user_idp');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sso_identities');
    }
};
