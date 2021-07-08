# Generated by default/object.tt
package Paws::Glue::SchemaId;
  use Moose;
  has RegistryName => (is => 'ro', isa => 'Str');
  has SchemaArn => (is => 'ro', isa => 'Str');
  has SchemaName => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Glue::SchemaId

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Glue::SchemaId object:

  $service_obj->Method(Att1 => { RegistryName => $value, ..., SchemaName => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Glue::SchemaId object:

  $result = $service_obj->Method(...);
  $result->Att1->RegistryName

=head1 DESCRIPTION

The unique ID of the schema in the Glue schema registry.

=head1 ATTRIBUTES


=head2 RegistryName => Str

The name of the schema registry that contains the schema.


=head2 SchemaArn => Str

The Amazon Resource Name (ARN) of the schema. One of C<SchemaArn> or
C<SchemaName> has to be provided.


=head2 SchemaName => Str

The name of the schema. One of C<SchemaArn> or C<SchemaName> has to be
provided.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Glue>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

