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
        Schema::create('sso_configurations', function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->string('slug', 100)->unique();
            $table->enum('type', ['saml', 'oidc', 'ldap']);
            $table->boolean('is_enabled')->default(true);
            $table->boolean('is_default')->default(false);
            $table->json('settings');
            $table->json('attribute_mapping')->nullable();
            $table->text('certificate')->nullable();
            $table->text('private_key')->nullable();
            $table->string('metadata_url', 500)->nullable();
            $table->text('metadata_xml')->nullable();
            $table->timestamps();

            $table->index(['type', 'is_enabled'], 'idx_type_enabled');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('sso_configurations');
    }
};
