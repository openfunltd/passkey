<?php
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
//common
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\AuthenticatorSelectionCriteria;
//serializer related
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\Encoder\JsonEncode;
//validator related
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;

class Passkey
{
    public static function generateCreationOptions($username, $user_id, $displayname)
    {
        //ingredients
        $RP_entity = PublicKeyCredentialRpEntity::create(getenv('APP_NAME'), self::getRPID());
        $user_entity = PublicKeyCredentialUserEntity::create($username, $user_id, $displayname);
        $challenge = random_bytes(32);
        $criteria = AuthenticatorSelectionCriteria::create(
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
        );
        $preference = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;

        //generate creation options
        $creation_options = PublicKeyCredentialCreationOptions::create(
            rp: $RP_entity,
            user: $user_entity,
            challenge: $challenge,
            authenticatorSelection: $criteria,
            attestation: $preference,
        );

        //serialize
        $creation_options_string = self::serialize('creation_options', $creation_options);

        return json_decode($creation_options_string);
    }

    public static function verifyCreation($credential_data, $creation_options_string)
    {
        //get validator
        $validator = self::getValidator('creation');

        //get PublicKeyCredential object
        $credential = self::deserialize('credential', $credential_data);

        //check client is in attestation step
        if (!$credential->response instanceof AuthenticatorAttestationResponse) {
            return (object) ['error' => 'Invalid credential response type'];
        }

        //get creation_options
        $creation_options = self::deserialize('creation_options', $creation_options_string);

        //vaildate
        try {
            $credential_source = $validator->check(
                $credential->response,
                $creation_options,
                self::getRPID(),
            );
        } catch (Throwable $e) {
            return (object) ['error' => $e->getMessage()];
        }

        //serialize
        $credential_source_string = self::serialize('credential_source', $credential_source);

        return json_decode($credential_source_string);
    }

    public static function generateAuthenticationOptions($credential_source_strings = [])
    {
        $allowed_credentials = [];
        foreach ($credential_source_strings as $credential_source_string) {
            $credential_source = self::deserialize('credential_source', $credential_source_string);
            $allowed_credentials[] = $credential_source->getPublicKeyCredentialDescriptor();
        }

        $authentication_options = PublicKeyCredentialRequestOptions::create(
            challenge: random_bytes(32),
            rpId: self::getRPID(),
            allowCredentials: $allowed_credentials, //empty array when using discoverable mode
            userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
        );

        $authentication_options_string = self::serialize('authentication_options', $authentication_options);

        return json_decode($authentication_options_string);
    }

    public static function verifyAuthentication($credential_source_string, $credential_data, $authentication_options_string, $user_id)
    {
        //get validator
        $validator = self::getValidator('request');

        //get PublicKeyCredential object
        $credential = self::deserialize('credential', $credential_data);

        //check client is in assertion step
        if (!$credential->response instanceof AuthenticatorAssertionResponse) {
            return (object) ['error' => 'Invalid credential response type'];
        }

        //get ingredients
        $credential_source = self::deserialize('credential_source', $credential_source_string);
        $authentication_options = self::deserialize('authentication_options', $authentication_options_string);

        //vaildate
        try {
            $updated_credential_source = $validator->check(
                $credential_source,
                $credential->response,
                $authentication_options,
                self::getRPID(),
                $user_id
            );
        } catch (Throwable $e) {
            return (object) ['error' => $e->getMessage()];
        }

        //serialize
        $updated_credential_source_string = self::serialize('credential_source', $updated_credential_source);

        return json_decode($updated_credential_source_string);
    }

    private static function serialize($type, $instance)
    {
        //get serializer
        $serializer = self::getSerializer();

        return $serializer->serialize(
            $instance,
            'json',
            [
                AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
            ]
        );
    }

    private static function deserialize($type, $data)
    {
        //get serializer
        $serializer = self::getSerializer();

        $type_class_mapping = [
            'credential' => PublicKeyCredential::class,
            'creation_options' => PublicKeyCredentialCreationOptions::class,
            'credential_source' => PublicKeyCredentialSource::class,
            'authentication_options' => PublicKeyCredentialRequestOptions::class,
        ];

        if ($type == 'credential') {
            $data = json_encode($data);
        }

        return $serializer->deserialize(
            $data,
            $type_class_mapping[$type],
            'json'
        );
    }

    private static function getValidator($type)
    {
        $csmFactory = new CeremonyStepManagerFactory();

        if ($type == 'creation') {
           $creation_CSM = $csmFactory->creationCeremony();
           return AuthenticatorAttestationResponseValidator::create($creation_CSM);
        }

        if ($type == 'request') {
           $request_CSM = $csmFactory->requestCeremony();
           return AuthenticatorAssertionResponseValidator::create($request_CSM);
        }
    }

    private static function getSerializer()
    {
        //create manager
        $attestation_statement_support_manager = AttestationStatementSupportManager::create();
        $attestation_statement_support_manager->add(NoneAttestationStatementSupport::create());

        //create serializer
        $factory = new WebauthnSerializerFactory($attestation_statement_support_manager);
        $serializer = $factory->create();

        return $serializer;
    }

    private static function getRPID()
    {
        $rp_id = (getenv('RP_ID') !== false) ? getenv('RP_ID') : $_SERVER['SERVER_NAME'];
        return $rp_id;
    }
}
